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
     * XPath-выражение, указывающее элемент для подписи. Учитывается методами /xml/v2/sign и
     * /xml/v3/sign. В /xml/v2/sign — куда вложить ds:Signature (если не задано, ds:Signature
     * добавляется в конец корневого элемента документа). В /xml/v3/sign — какой элемент вырезать,
     * подписать и вставить обратно (обязателен по смыслу, иначе будет подписан весь документ).
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
