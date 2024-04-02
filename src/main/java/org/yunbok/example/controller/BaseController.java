package org.yunbok.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BaseController {

    @GetMapping("/hello")
    public String hello(@RequestParam(value = "name", defaultValue = "World") String name) {
        return String.format("Hello %s!", name);
    }

    @GetMapping("/test")
    public String test(@RequestParam(value = "name", defaultValue = "World") String name) {
        return String.format("test %s!", name);
    }

    @GetMapping("/admin")
    public String admin(@RequestParam(value = "name", defaultValue = "World") String name) {
        return String.format("admin %s!", name);
    }

}
