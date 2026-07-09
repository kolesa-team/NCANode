package kz.ncanode.dto.request;

import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import javax.validation.constraints.NotEmpty;

@Jacksonized
@Data
@Builder
public class SignerRequest {

    @NotEmpty
    private String key;

    @NotEmpty
    private String password;

    private String keyAlias;

    private String referenceUri;

    /**
     * XPath-выражение, указывающее элемент для подписи. Учитывается методом /xml/v2/sign —
     * какой элемент вырезать, подписать и вставить обратно (обязателен по смыслу, иначе будет
     * подписан весь документ).
     */
    private String xpath;
}
