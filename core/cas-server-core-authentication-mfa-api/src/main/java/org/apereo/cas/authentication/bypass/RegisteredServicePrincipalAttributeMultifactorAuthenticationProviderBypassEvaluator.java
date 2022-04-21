package org.apereo.cas.authentication.bypass;

import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.MultifactorAuthenticationProvider;
import org.apereo.cas.services.RegisteredService;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import javax.servlet.http.HttpServletRequest;

/**
 * Multifactor Bypass based on both - the enabled flag and Principal Attributes.
 *
 * If principal attributes are not set, it simply considers the enabled flag alone.
 *
 * @author Travis Schmidt
 * @author Dmitriy Kopylenko
 * @since 6.0
 */
@Slf4j
@Getter
public class RegisteredServicePrincipalAttributeMultifactorAuthenticationProviderBypassEvaluator extends BaseMultifactorAuthenticationProviderBypassEvaluator {
    private static final long serialVersionUID = -6123435418344342672L;


    public RegisteredServicePrincipalAttributeMultifactorAuthenticationProviderBypassEvaluator(final String providerId) {
        super(providerId);
    }

    @Override
    public boolean shouldMultifactorAuthenticationProviderExecuteInternal(final Authentication authentication,
                                                                          final RegisteredService registeredService,
                                                                          final MultifactorAuthenticationProvider provider,
                                                                          final HttpServletRequest request) {
        if (registeredService == null) {
            return true;
        }

        val mfaPolicy = registeredService.getMultifactorPolicy();
        val shouldProceed = mfaPolicy == null || !mfaPolicy.isBypassEnabled();

        if (!shouldProceed) {
            if(StringUtils.isBlank(mfaPolicy.getBypassPrincipalAttributeName()) || StringUtils.isBlank(mfaPolicy.getBypassPrincipalAttributeValue())) {
                return false;
            }

            val principal = resolvePrincipal(authentication.getPrincipal());
            val bypass = locateMatchingAttributeValue(mfaPolicy.getBypassPrincipalAttributeName(),
                mfaPolicy.getBypassPrincipalAttributeValue(),
                principal.getAttributes(), true);
            if (bypass) {
                LOGGER.debug("Bypass rules for principal [{}] indicate the request may be ignored", principal.getId());
                return false;
            }
        }
        return true;
    }
}
