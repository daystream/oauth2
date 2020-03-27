package oauth2.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

@RestController
public class HelloController {

    @GetMapping("/api/hi")
    public String say(@RequestParam("code") String code, @RequestParam("state") String state
            /*,OAuth2Authentication auth,@AuthenticationPrincipal(expression="name") String name*/) {

        RestTemplate restTemplate = new RestTemplate();
        String credentials = "clientapp:123";
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", "Basic " + encodedCredentials);
        HttpEntity<String> request = new HttpEntity<String>(headers);
        String access_token_url = "http://localhost:8080/oauth/token";
        access_token_url += "?client_id=clientapp";
        access_token_url += "&code=" + code;
        access_token_url += "&grant_type=authorization_code";
        ResponseEntity<String> response = restTemplate.exchange(access_token_url, HttpMethod.POST, request, String.class);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = null;
        try {
            node = mapper.readTree(response.getBody());
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        String token = node.path("access_token").asText();
        System.out.println(token);

        HttpHeaders headers1 = new HttpHeaders();
        headers1.add("Authorization", "Bearer " + token);
        HttpEntity<String> entity = new HttpEntity<>(headers1);
        String url="http://localhost:8080/user/my";
        ResponseEntity<String> my = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        return my.getBody();
    }

    @RequestMapping("/user/my")
    @PostAuthorize ("hasRole('ROLE_USER')")
    public String my(OAuth2Authentication auth) {
        return "Hello "+auth.getUserAuthentication().getPrincipal();
    }

}