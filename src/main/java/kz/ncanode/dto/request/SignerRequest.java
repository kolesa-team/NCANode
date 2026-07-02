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
     * Если true и referenceUri указывает на конкретный элемент (вида "#id"),
     * ds:Signature вкладывается внутрь этого элемента вместо конца корневого элемента документа.
     */
    @Builder.Default
    private boolean insertSignatureAtReference = false;
}
