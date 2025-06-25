package org.example.resource.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class DataController {
    @GetMapping("/api/data")
    public Map<String, String> getData() {
        return Map.of("message", "This is protected data from resource server.");
    }
}
