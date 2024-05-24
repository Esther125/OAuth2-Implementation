package com.huongdanjava.springauthorizationserver.data;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenBody {
    String token;
    String userName;
    String password;
    String client_id;
    String state;
}

