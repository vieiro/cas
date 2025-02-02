package org.apereo.cas.services.web;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.context.support.ResourceBundleMessageSource;

import javax.annotation.Nonnull;
import java.util.Locale;
import java.util.ResourceBundle;

/**
 * This is {@link CasThemeResourceBundleMessageSource}.
 *
 * @author Misagh Moayyed
 * @since 6.6.0
 */
@Slf4j
public class CasThemeResourceBundleMessageSource extends ResourceBundleMessageSource {
    @Nonnull
    @Override
    protected ResourceBundle doGetBundle(
        @Nonnull
        final String basename,
        @Nonnull
        final Locale locale) {
        try {
            val bundle = ResourceBundle.getBundle(basename, locale, getBundleClassLoader());
            if (bundle != null && !bundle.keySet().isEmpty()) {
                return bundle;
            }
        } catch (final Exception e) {
            LOGGER.debug(e.getMessage(), e);
        }
        return null;
    }
}
