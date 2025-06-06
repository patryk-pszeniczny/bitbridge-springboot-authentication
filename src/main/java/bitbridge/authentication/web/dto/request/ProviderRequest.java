package bitbridge.authentication.web.dto.request;

import bitbridge.authentication.domain.model.User;
import lombok.Data;

@Data
public class ProviderRequest {
    private String providerId;
    private User user;
}
