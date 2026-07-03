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
     * XPath-выражение, указывающее куда вложить ds:Signature. Учитывается только методом
     * /xml/v2/sign. Если не задано, ds:Signature добавляется в конец корневого элемента документа.
     */
    private String xpath;

    /**
     * Учитывается только методом /xml/v2/sign. Если true, для ds:CanonicalizationMethod
     * используется Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS (exclusive canonicalization),
     * иначе — алгоритм канонизации по умолчанию.
     */
    @Builder.Default
    private boolean exclusive = false;
}
