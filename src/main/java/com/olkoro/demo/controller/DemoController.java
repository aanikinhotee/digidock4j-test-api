package com.olkoro.demo.controller;

import java.net.URL;
import java.security.cert.X509Certificate;

import org.digidoc4j.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@CrossOrigin(origins = "*")
public class DemoController {

    @PostMapping("/file")
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") MultipartFile file) {
        System.out.println("test");
        return ResponseEntity.status(HttpStatus.OK).body("test");
    }

    @GetMapping("/test")
    public ResponseEntity<String> test() {
        System.out.println("test");
        return ResponseEntity.status(HttpStatus.OK).body("test");
    }
}
