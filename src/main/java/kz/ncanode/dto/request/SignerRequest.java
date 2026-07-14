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
     * XPath-выражение, указывающее элемент для подписи методом /xml/v2/sign — какой элемент
     * вырезать, подписать и вставить обратно.
     * <p>
     * Namespace-префиксы не поддерживаются (NamespaceContext не задаётся) — используйте форму
     * через local-name(), например {@code /*[local-name()='Envelope']/*[local-name()='Body']}.
     * <p>
     * Если выражение совпадает с несколькими элементами, подписывается первый в порядке документа.
     * Если xpath не задан (пустой), подписывается корневой элемент документа целиком.
     */
    private String xpath;
}
