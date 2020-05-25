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

import org.digidoc4j.*;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class FileSignerTest {

    private FileSigner fileSigner;
    private static Configuration configuration = new Configuration(Configuration.Mode.TEST);

    @Before
    public void setUp() throws Exception {
        fileSigner = new FileSigner();
        fileSigner.setConfiguration(configuration);
    }

    @Test
    public void createContainerFromFile() throws Exception {
        DataFile file = createFile("test.txt", "Test data to sign");
        Container container = fileSigner.createContainer(file);
        assertEquals(1, container.getDataFiles().size());
    }

    @Test
    public void gettingDataToSign() throws Exception {
        DataFile file = createFile("test.txt", "Test data to sign");
        String certificateInHex = TestSigningData.getSigningCertificateInHex("RSA");
        Container container = fileSigner.createContainer(file);
        DataToSign dataToSign = fileSigner.getDataToSign(container, certificateInHex);
        assertTrue(dataToSign.getDataToSign().length > 0);
    }

    @Test
    public void signDocumentWithRSA() throws Exception {
        DataFile file = createFile("test.txt", "Test data to sign");
        String certificateInHex = TestSigningData.getSigningCertificateInHex("RSA");
        Container container = fileSigner.createContainer(file);
        DataToSign dataToSign = fileSigner.getDataToSign(container, certificateInHex);
        byte[] data = dataToSign.getDataToSign();
        String signatureInHex = TestSigningData.signData(data, DigestAlgorithm.SHA256, "RSA");
        fileSigner.signContainer(container, dataToSign, signatureInHex);
        assertEquals(1, container.getSignatures().size());
        assertTrue(container.validate().isValid());
    }

    @Test
    public void signDocumentWithEC() throws Exception {
        DataFile file = createFile("test.txt", "Test data to sign");
        String certificateInHex = TestSigningData.getSigningCertificateInHex("EC");
        Container container = fileSigner.createContainer(file);
        DataToSign dataToSign = fileSigner.getDataToSign(container, certificateInHex);
        byte[] data = dataToSign.getDataToSign();
        String signatureInHex = TestSigningData.signData(data, DigestAlgorithm.SHA256, "EC");
        fileSigner.signContainer(container, dataToSign, signatureInHex);
        assertEquals(1, container.getSignatures().size());
        assertTrue(container.validate().isValid());
    }

    private DataFile createFile(String name, String data) {
        DataFile file = new DataFile(data.getBytes(), name, "text/plain");
        return file;
    }
}
