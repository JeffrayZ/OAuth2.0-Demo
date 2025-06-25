package org.example.client.controller;

import jakarta.annotation.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Controller
public class WebController {

    @Resource
    private RestTemplate restTemplate;

    @GetMapping("/")
    public String loginPage() {
        // 重定向到登录页面
        return "redirect:/login.html";
    }

    @GetMapping("/index")
    public String indexPage(Model model, @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient client) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(client.getAccessToken().getTokenValue());

        HttpEntity<Void> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                    "http://localhost:8082/api/data", HttpMethod.GET, request, Map.class);
            Map<String, Object> data = response.getBody();
            model.addAttribute("data", data);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "index"; // index.html
    }
}
