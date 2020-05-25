/**
 * DigiDoc4j Hwcrypto Demo
 *
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.olkoro.demo.signature;

import org.apache.commons.codec.binary.Hex;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;

@Service
public class TestSigningData {

    public static final String TEST_PKI_CONTAINER = "src/main/resources/signout.p12";
    public static final String TEST_PKI_CONTAINER_PASSWORD = "test";
    public static final String TEST_ECPKI_CONTAINER = "src/main/resources/MadDogOY.p12";
    public static final String TEST_ECPKI_CONTAINER_PASSWORD = "test";

    public static String getSigningCertificateInHex(String keyMode) {
        try {
            PKCS12SignatureToken token;
            if ("RSA".equals(keyMode)) token = getRSAToken();
            else token = getECToken();
            X509Certificate certificate = token.getCertificate();
            byte[] derEncodedCertificate = certificate.getEncoded();
            String hexString = Hex.encodeHexString(derEncodedCertificate);
            return hexString;
        } catch (Exception e) {
            throw new RuntimeException("Certificate loading failed", e);
        }
    }

    public static String signData(byte[] dataToSign, DigestAlgorithm digestAlgorithm, String keyMode) {
        PKCS12SignatureToken token;
        if ("RSA".equals(keyMode)) token = getRSAToken();
        else token = getECToken();
        byte[] signatureValue = token.sign(digestAlgorithm, dataToSign);
        String hexString = Hex.encodeHexString(signatureValue);
        return hexString;
    }

    private static PKCS12SignatureToken getRSAToken() {
        return getToken(TEST_PKI_CONTAINER, TEST_PKI_CONTAINER_PASSWORD);
    }

    private static PKCS12SignatureToken getECToken() {
        return getToken(TEST_ECPKI_CONTAINER, TEST_ECPKI_CONTAINER_PASSWORD);
    }

    private static PKCS12SignatureToken getToken(String pkiContainer, String pkiContainerPassword) {
        try {
            PKCS12SignatureToken token = new PKCS12SignatureToken(pkiContainer, pkiContainerPassword);
            return token;
        } catch (Exception e) {
            throw new RuntimeException("Loading signer token failed");
        }
    }
}
