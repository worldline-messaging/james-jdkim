/****************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one   *
 * or more contributor license agreements.  See the NOTICE file *
 * distributed with this work for additional information        *
 * regarding copyright ownership.  The ASF licenses this file   *
 * to you under the Apache License, Version 2.0 (the            *
 * "License"); you may not use this file except in compliance   *
 * with the License.  You may obtain a copy of the License at   *
 *                                                              *
 *   http://www.apache.org/licenses/LICENSE-2.0                 *
 *                                                              *
 * Unless required by applicable law or agreed to in writing,   *
 * software distributed under the License is distributed on an  *
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY       *
 * KIND, either express or implied.  See the License for the    *
 * specific language governing permissions and limitations      *
 * under the License.                                           *
 ****************************************************************/

package org.apache.james.jdkim;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.impl.BodyHasherImpl;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;
import org.apache.james.mime4j.MimeException;

public class DKIMSigner extends DKIMCommon {

	private PrivateKey privateKey;
	private String signatureRecordTemplate;

	public DKIMSigner(String signatureRecordTemplate, PrivateKey privateKey) {
		this.privateKey = privateKey;
		this.signatureRecordTemplate = signatureRecordTemplate;
	}

	public SignatureRecord newSignatureRecord(String record) {
		return new SignatureRecordImpl(record);
	}

	public BodyHasher newBodyHasher(SignatureRecord signRecord) throws NoSuchAlgorithmException {
		return new BodyHasherImpl(signRecord);
	}

	public String sign(InputStream is)
			throws IOException, FailException {
		Message message;
		try {
			try {
				message = new Message(is);
			} catch (MimeException e1) {
				throw new PermFailException("MIME parsing exception: "+e1.getMessage(), e1);
			}
			SignatureRecord srt = newSignatureRecord(signatureRecordTemplate);
			try {
				BodyHasher bhj = newBodyHasher(srt);

				// simultaneous computation of all the hashes.
				DKIMCommon.streamCopy(message.getBodyInputStream(), bhj.getOutputStream());
		
				return sign(message, bhj);
			} catch (NoSuchAlgorithmException e) {
				throw new PermFailException("Unknown algorythm: "+e.getMessage(), e);
			}
	
		} finally {
			is.close();
		}
	}

	public String sign(Headers message, BodyHasher bhj)
			throws PermFailException {
		byte[] computedHash = bhj.getDigest();
		String newField = "DKIM-Signature: "+signatureRecordTemplate.replaceAll("bh=[^;]*", "bh="+new String(Base64.encodeBase64(computedHash)));

		List headers = bhj.getSignatureRecord().getHeaders();
		try {
			// TODO handle b= in SignatureRecord.
			// whenever any tag is changed the b should be invalidated and the text representation lost.
			// whenever the b value is regenerated it should also be associated with the right test representation.
			// we need a method to "regenerate the text representation" and to retrieve it when it is valid.
			byte[] signatureHash = signatureSign(message, newField,
					bhj.getSignatureRecord(), privateKey, headers);
			newField = newField.replaceAll("b=[^;]*", "b="+new String(Base64.encodeBase64(signatureHash)));
			return newField;
		} catch (InvalidKeyException e) {
			throw new PermFailException("Invalid key: "+e.getMessage(), e);
		} catch (NoSuchAlgorithmException e) {
			throw new PermFailException("Unknown algorythm: "+e.getMessage(), e);
		} catch (SignatureException e) {
			throw new PermFailException("Signing exception: "+e.getMessage(), e);
		}
	}

	private byte[] signatureSign(Headers h, String signatureStub, SignatureRecord sign,
			PrivateKey key, List headers)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, PermFailException {
	
		Signature signature = Signature.getInstance(sign.getHashMethod().toString().toUpperCase()+"with"+sign.getHashKeyType().toString().toUpperCase());
		signature.initSign(key);
		signatureCheck(h, sign, headers, signatureStub, signature);
		return signature.sign();
	}

	/**
	 * Generate a PrivateKey from a Base64 encoded private key.
	 * 
	 * In order to generate a valid PKCS8 key when you have a PEM key you can do this:
	 * <code>
	 * openssl pkcs8 -topk8 -inform PEM -in rsapriv.pem -outform DER -nocrypt -out rsapriv.der
	 * </code>
	 * And then base64 encode the content.
	 * 
	 * @param privateKeyPKCS8 a Base64 encoded string of the RSA key in PKCS8 format
	 * @return the PrivateKey
	 * @throws NoSuchAlgorithmException if RSA is unknown
	 * @throws InvalidKeySpecException on bad input key
	 */
	public static PrivateKey getPrivateKey(String privateKeyPKCS8)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] encKey = Base64.decodeBase64( privateKeyPKCS8.getBytes() );
	    // byte[] encKey = privateKey.getBytes();
	    PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encKey);
	    KeyFactory keyFactory;
		keyFactory = KeyFactory.getInstance("RSA");
	    PrivateKey privKey = keyFactory.generatePrivate(privSpec);
		return privKey;
	}

}
