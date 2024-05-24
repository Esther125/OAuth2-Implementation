package com.huongdanjava.springauthorizationserver.data;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class S2SOauthReq {
    private String yourId;
    private String oauthId;
    private String oauthSecret;
}
