/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.captcha.recaptcha.internal;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Named;
import javax.inject.Singleton;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.xwiki.captcha.AbstractCaptcha;
import org.xwiki.captcha.CaptchaException;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.web.XWikiRequest;

/**
 * Google reCAPTCHA based CAPTCHA implementation.
 *
 * @version $Id$
 * @since 10.8RC1
 */
@Component
@Named("recaptcha")
@Singleton
public class ReCaptchaCaptcha extends AbstractCaptcha
{
    private static final List<String> RECAPTCHA_SPACE_LIST = Arrays.asList(XWiki.SYSTEM_SPACE, "Captcha", "reCAPTCHA");

    private static final LocalDocumentReference CONFIGURATION_DOCUMENT_REFERENCE =
        new LocalDocumentReference(RECAPTCHA_SPACE_LIST, "Configuration");

    private static final LocalDocumentReference CONFIGURATION_CLASS_REFERENCE =
        new LocalDocumentReference(RECAPTCHA_SPACE_LIST, "ConfigurationClass");

    private static final LocalDocumentReference DISPLAYER_DOCUMENT_REFERENCE =
        new LocalDocumentReference(RECAPTCHA_SPACE_LIST, "Displayer");

    private static final String SECRET_KEY_PARAMETER = "secretKey";

    private static final Map<String, Object> DEFAULT_PARAMETERS = new HashMap<>();
    {
        DEFAULT_PARAMETERS.put("siteKey", "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI");
        DEFAULT_PARAMETERS.put(SECRET_KEY_PARAMETER, "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe");
        DEFAULT_PARAMETERS.put("theme", "light");
        DEFAULT_PARAMETERS.put("size", "normal");
        DEFAULT_PARAMETERS.put("tabindex", 0);
    }

    @Override
    protected LocalDocumentReference getDisplayerDocumentReference()
    {
        return DISPLAYER_DOCUMENT_REFERENCE;
    }

    @Override
    protected LocalDocumentReference getConfigurationDocumentReference()
    {
        return CONFIGURATION_DOCUMENT_REFERENCE;
    }

    @Override
    protected LocalDocumentReference getConfigurationClassReference()
    {
        return CONFIGURATION_CLASS_REFERENCE;
    }

    @Override
    protected Map<String, Object> getDefaultParameters()
    {
        return DEFAULT_PARAMETERS;
    }

    @Override
    protected boolean validate(Map<String, Object> captchaParameters) throws Exception
    {
        XWikiContext context = getContext();
        XWiki xwiki = context.getWiki();
        XWikiRequest request = context.getRequest();

        // Validate the answer.
        String remoteIp = request.getRemoteAddr();
        String answer = request.getParameter("g-recaptcha-response");
        String secretSiteKey = (String) captchaParameters.get(SECRET_KEY_PARAMETER);

        // Build the URL.
        String url = String.format("https://www.google.com/recaptcha/api/siteverify?secret=%s&response=%s&remoteip=%s",
            secretSiteKey, answer, remoteIp);

        // Call it and parse the response.
        String jsonString = xwiki.getURLContent(url, context);
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonResponse = (JSONObject) jsonParser.parse(jsonString);

        boolean result = Boolean.TRUE.equals(jsonResponse.get("success"));

        // Mention possible error codes.
        if (!result) {
            JSONArray errorCodes = (JSONArray) jsonResponse.get("error-codes");
            // If the error is other than "missing-input-response" (which simply means the user did not validate the
            // CAPTCHA before submitting the form), then we might be dealing with a configuration or otherwise
            // significant problem that we need to fix.
            if (errorCodes != null && !errorCodes.contains("missing-input-response")) {
                throw new CaptchaException("reCAPTCHA server replied: " + jsonString, null);
            }
        }

        return result;
    }
}
