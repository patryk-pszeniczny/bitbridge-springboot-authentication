package bitbridge.authentication.web.dto.request;

import bitbridge.authentication.domain.model.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProviderRequest {
    private String providerId;
    private User user;
}
