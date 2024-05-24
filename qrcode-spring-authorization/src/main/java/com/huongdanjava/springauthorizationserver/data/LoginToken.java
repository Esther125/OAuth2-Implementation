package com.huongdanjava.springauthorizationserver.data;

import com.google.gson.Gson;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginToken {

    private String ip;
    private long t;
    private long ttl;
    private String token;

    private String client_id;
    private String state;

    public String getRedisKey() {
        return getRedisKey(this.getIp());
    }

    public String toJsonStr() {
        return new Gson().toJson(this);
    }

    // Get redis key for "registration token".
    public static String getRedisKey(String ip) {
        return "lt#" + ip;
    }

    public static String getRedisKey(LoginToken loginToken) {
        return getRedisKey(loginToken.getIp());
    }

    public static LoginToken fromJsonStr(String str) {
        return new Gson().fromJson(str, LoginToken.class);
    }
}
