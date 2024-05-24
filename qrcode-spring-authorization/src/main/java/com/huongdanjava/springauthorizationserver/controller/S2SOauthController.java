package com.huongdanjava.springauthorizationserver.controller;

import com.huongdanjava.springauthorizationserver.data.LoginToken;
import com.huongdanjava.springauthorizationserver.data.S2SCredential;
import com.huongdanjava.springauthorizationserver.data.S2SOauthReq;
import com.huongdanjava.springauthorizationserver.data.S2SRegisterReq;
import com.huongdanjava.springauthorizationserver.service.RedisService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/s2s-oauth")
public class S2SOauthController {
    private static final Logger logger = LoggerFactory.getLogger(S2SOauthController.class);

    @Autowired
    RedisService redisService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody S2SRegisterReq s2SRegisterReq){
        String serverId = null;
        if(s2SRegisterReq.getServerName()!=null && s2SRegisterReq.getServerUsage() != null){
            serverId = s2SRegisterReq.getServerName()+"-"+s2SRegisterReq.getServerUsage();
        }

        if (redisService.hasKey(serverId)){
            return ResponseEntity.ok("The Server is registered. ID: "+serverId);
        }

        String secret = UUID.randomUUID().toString().replace("-", "");
//                s2SRegisterReq.getServerName() + ":" +
//                s2SRegisterReq.getServerUsage();
        logger.info("Attempting to register server with ID: {}", serverId);

        S2SCredential s2SCredential = S2SCredential.builder()
                .serverId(serverId)
                .serverSecret(secret)
                .build();

        try {
            redisService.set(serverId, secret);
            logger.info("Successfully registered server in Redis with ID: {}", serverId);
            return ResponseEntity.status(HttpStatus.OK).body(s2SCredential);
        } catch (Exception e) {
            logger.error("Error registering server in Redis: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Registration failed");
        }
    }

    @PostMapping("/oauth")
    public ResponseEntity<?> oauth(@RequestBody S2SOauthReq s2SOauthReq){
        String yourId = s2SOauthReq.getYourId();
        String oauthId = s2SOauthReq.getOauthId();
        String oauthSecret = s2SOauthReq.getOauthSecret();

        boolean isValid = false;
        String realSecrect = null;

        if(redisService.hasKey(yourId)){
            if(redisService.hasKey(oauthId)){
                realSecrect = (String) redisService.get(oauthId);
            }
        }

        if(realSecrect != null){
            if(realSecrect.equals(oauthSecret)){
                return ResponseEntity.status(HttpStatus.OK).body("Valid Secret for ID: "+ oauthId);
            }else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Secret for ID: " + oauthId);
            }
        }else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Please ensure that the IDs are correct.");
        }

    }

    @GetMapping("/renew/{yourId}")
    public ResponseEntity<?> renewSecret(@PathVariable("yourId") String yourId){
        if(redisService.hasKey(yourId)){
            String newSecret = UUID.randomUUID().toString().replace("-", "");
            redisService.set(yourId,newSecret);
            S2SCredential s2SCredential = S2SCredential.builder()
                    .serverId(yourId)
                    .serverSecret(newSecret)
                    .build();
            return ResponseEntity.status(HttpStatus.OK).body(s2SCredential);
        }else{
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Server ID not found: " + yourId);
        }
    }

}
