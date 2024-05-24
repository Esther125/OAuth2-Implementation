package com.huongdanjava.springauthorizationserver.data;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class S2SCredential {
    private String serverId;
    private String serverSecret;
}
