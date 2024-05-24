package com.huongdanjava.springauthorizationserver.data;

import com.google.gson.Gson;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
public class LoginConsumeToken {
    private String result;
    public String toJsonStr() {
        return new Gson().toJson(this);
    }
    // Get redis key for "login token consumption".
    public static String getRedisKey(String token) {
        return "ltc#" + token;
    }
    public static String getRedisKey(LoginToken loginToken) {
        return getRedisKey(loginToken.getToken());
    }

    public static LoginConsumeToken fromJsonStr(String str) {
        return new Gson().fromJson(str, LoginConsumeToken.class);
    }
}
