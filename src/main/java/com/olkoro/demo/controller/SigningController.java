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
package com.olkoro.demo.controller;

import com.olkoro.demo.model.Digest;
import com.olkoro.demo.model.Result;
import com.olkoro.demo.model.SigningSessionData;
import com.olkoro.demo.signature.FileSigner;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import org.apache.commons.lang3.StringUtils;
import org.apache.xalan.xsltc.dom.SimpleResultTreeImpl;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@CrossOrigin(origins = "*")
public class SigningController {

    private static final Logger log = LoggerFactory.getLogger(SigningController.class);
    @Autowired
    private SigningSessionData session;
    @Autowired
    private FileSigner signer;

    @RequestMapping(value="/upload", method= RequestMethod.POST)
    public Result handleUpload(@RequestParam MultipartFile file) {
        System.out.println("Handling file upload for file "+file.getOriginalFilename());
        try {
            byte[] fileBytes = file.getBytes();
            String fileName = file.getOriginalFilename();
            String mimeType = file.getContentType();
            DataFile dataFile = new DataFile(fileBytes, fileName, mimeType);

            multipartFileToFile(file, Paths.get("C:\\Users\\Laptop\\Downloads\\demo\\demo"));

            Container container = signer.createContainer(dataFile);

            session.setContainer(container);
            return Result.resultOk();
        } catch (IOException e) {
            log.error("Error reading bytes from uploaded file " + file.getOriginalFilename(), e);
        }
        return Result.resultUploadingError();
    }

    public void multipartFileToFile(
            MultipartFile multipart,
            Path dir
    ) throws IOException {
        System.out.println("NB! path"+dir);
        Path filepath = Paths.get(dir.toString(), multipart.getOriginalFilename());
        multipart.transferTo(new File(String.valueOf(filepath)));
    }

    @RequestMapping(value="/generateHash", method = RequestMethod.POST)
    public Digest generateHash(@RequestParam String certInHex) {

        System.out.println("Generating hash from cert " + StringUtils.left(certInHex, 10) + "...");
        System.out.println("NB! /generateHash");
        System.out.println("NB! certInHex "+ certInHex);
        Container container = session.getContainer();

        container = ContainerBuilder.
                aContainer().
                withDataFile("doc.txt", "text/plain").
                build();

        Digest digest = new Digest();
        try {
            DataToSign dataToSign = signer.getDataToSign(container, certInHex);
            session.setDataToSign(dataToSign);
            String dataToSignInHex =
                    DatatypeConverter.printHexBinary(DSSUtils.digest(DigestAlgorithm.SHA256, dataToSign.getDataToSign()));
            System.out.println("NB! dataToSignInHex "+dataToSignInHex);
            digest.setHex(dataToSignInHex);
            digest.setResult(Result.OK);
        } catch (Exception e) {
            log.error("Error Calculating data to sign", e);
            digest.setResult(Result.ERROR_GENERATING_HASH);
        }
        return digest;
    }

    @RequestMapping(value="/createContainer", method = RequestMethod.POST)
    public Result createContainer(@RequestParam String signatureInHex, @RequestParam String certInHex) {

        System.out.println("Creating container for signature " + StringUtils.left(signatureInHex, 10) + "...");
        System.out.println("NB! /createContainer");
        System.out.println("NB! signatureInHex "+signatureInHex);
        System.out.println("NB! certInHex "+certInHex);
        DataToSign dataToSign = session.getDataToSign();
        try {
            Container container = session.getContainer();

            container = ContainerBuilder.
                    aContainer().
                    withDataFile("doc.txt", "text/plain").
                    build();
            dataToSign = signer.getDataToSign(container, certInHex);

            String dataToSignInHex =
                    DatatypeConverter.printHexBinary(DSSUtils.digest(DigestAlgorithm.SHA256, dataToSign.getDataToSign()));
            System.out.println("NB! dataToSignInHex "+dataToSignInHex);

            signer.signContainer(container, dataToSign, signatureInHex);
            //session.setContainer(container);
            return Result.resultOk();
        } catch (Exception e) {
            log.error("Error Signing document", e);
        }
        return Result.resultSigningError();
    }

}
