package kz.ncanode.dto.tsp;

import lombok.*;

import java.util.Date;

@Data
@Builder
@AllArgsConstructor
@Getter
@NoArgsConstructor
public class TspInfo {
    private String serialNumber;
    private Date genTime;
    private String policy;
    private String tsa;
    private String tspHashAlgorithm;
    private String hash;
}
