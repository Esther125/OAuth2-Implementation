package com.huongdanjava.springauthorizationserver.data;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class WaitLoginConsumeBody {
    String token;
    String ip;
    private Map<String,String> options;
}
