package com.huongdanjava.springauthorizationserver.data;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
public class ClientDetails {
    private String client_id;
    private String state;
}
