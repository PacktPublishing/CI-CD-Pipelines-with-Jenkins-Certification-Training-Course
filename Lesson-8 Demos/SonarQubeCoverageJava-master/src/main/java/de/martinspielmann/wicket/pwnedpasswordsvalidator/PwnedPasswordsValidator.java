package de.martinspielmann.wicket.pwnedpasswordsvalidator;

import org.apache.commons.io.IOUtils;
import org.apache.wicket.util.string.Strings;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidationError;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Checks if a given password has been disclosed in a data breach using API of
 * <a href="https://haveibeenpwned.com/">https://haveibeenpwned.com/</a> More
 * details at <a href=
 * "https://haveibeenpwned.com/API/v2#PwnedPasswords">https://haveibeenpwned.com/API/v2#PwnedPasswords</a>
 *
 * @author Martin Spielmann
 */
public class PwnedPasswordsValidator implements IValidator<String> {

	private static final long serialVersionUID = 1L;

	private static final Logger LOG = LoggerFactory.getLogger(PwnedPasswordsValidator.class);

	private static final String API_URL = "https://api.pwnedpasswords.com/range/%s";

	private final boolean failOnUnknownError;
	private final RateLimitExceededBehavior rateLimitExceededBehavior;
	private final Proxy proxy;

	/**
	 * Creates a new PwnedPasswordsValidator with default configuration. If an error
	 * occurs during validation, the validated password will be treated as invalid.
	 * If the rate limit of the
	 * <a href="https://haveibeenpwned.com/API/v2#PwnedPasswords">have i been pwned?
	 * API</a> is reached, the current Thread will sleep for two seconds before
	 * another validation will be triggered. <strong>Warning:</strong> this might
	 * have negative impact on your application responsiveness depending on your app
	 * design.
	 */
	public PwnedPasswordsValidator() {
		this(true, RateLimitExceededBehavior.RETRY);
	}

	/**
	 * Creates a new PwnedPasswordsValidator
	 *
	 * @param failOnUnknownError
	 *            If {@code true}, if an error occurs during validation, the
	 *            validated password will be treated as invalid. Else errors will be
	 *            ignored and the password will be treated as valid.
	 * @param rateLimitExceededBehavior
	 *            If set to {@link RateLimitExceededBehavior#IGNORE}, if rate limit
	 *            is exceeded during validation, the validated password will be
	 *            treated as valid. If set to
	 *            {@link RateLimitExceededBehavior#RETRY}, if rate limit is exceeded
	 *            during validation, the {@code Thread} will sleep for two seconds
	 *            and validation will be retried afterwards. If set to
	 *            {@link RateLimitExceededBehavior#FAIL}, if rate limit is exceeded
	 *            during validation, the validated password will be treated as
	 *            invalid.
	 */
	public PwnedPasswordsValidator(boolean failOnUnknownError, RateLimitExceededBehavior rateLimitExceededBehavior) {
		this(failOnUnknownError, rateLimitExceededBehavior, null);
	}

	/**
	 * Creates a new PwnedPasswordsValidator
	 *
	 * @param failOnUnknownError
	 *            If {@code true}, if an error occurs during validation, the
	 *            validated password will be treated as invalid. Else errors will be
	 *            ignored and the password will be treated as valid.
	 * @param rateLimitExceededBehavior
	 *            If set to {@link RateLimitExceededBehavior#IGNORE}, if rate limit
	 *            is exceeded during validation, the validated password will be
	 *            treated as valid. If set to
	 *            {@link RateLimitExceededBehavior#RETRY}, if rate limit is exceeded
	 *            during validation, the {@code Thread} will sleep for two seconds
	 *            and validation will be retried afterwards. If set to
	 *            {@link RateLimitExceededBehavior#FAIL}, if rate limit is exceeded
	 *            during validation, the validated password will be treated as
	 *            invalid.
	 * @param proxy
	 *            the proxy server
	 */
	public PwnedPasswordsValidator(boolean failOnUnknownError, RateLimitExceededBehavior rateLimitExceededBehavior,
			Proxy proxy) {
		this.failOnUnknownError = failOnUnknownError;
		this.rateLimitExceededBehavior = rateLimitExceededBehavior;
		this.proxy = proxy;
	}

	@Override
	public void validate(IValidatable<String> validatable) {
		String pw = validatable.getValue();
		Status status = getResponseStatus(pw);

		switch (status) {
		case UNKNOWN_API_ERROR:
			if (shouldFailOnUnknownError()) {
				validatable.error(decorate(new ValidationError(this, "unknownError"), validatable));
			}
			break;
		case PASSWORD_PWNED:
			validatable.error(decorate(new ValidationError(this, "pwned"), validatable));
			break;
		case TOO_MANY_REQUESTS:
			handleToManyRequests(validatable);
			break;
		case PASSWORD_OK:
			// great. password not pwned.
			break;
		}
	}

	protected void handleToManyRequests(IValidatable<String> validatable) {
		switch (getRateLimitExceededBehavior()) {
		case FAIL:
			validatable.error(decorate(new ValidationError(this, "tooManyRequests"), validatable));
			break;
		case RETRY:
			try {
				Thread.sleep(2000);
			} catch (InterruptedException e) {
				LOG.error("Error waiting to request pwned passwords", e);
				Thread.currentThread().interrupt();
			}
			validate(validatable);
			break;
		case IGNORE:
			break;
		}
	}

	protected Status getResponseStatus(String pw) {
        try {
        	
            HttpURLConnection c;
            if (getProxy() != null) {
                c = (HttpURLConnection) getApiUrl(pw).openConnection(getProxy());
            } else {
                c = (HttpURLConnection) getApiUrl(pw).openConnection();
            }
            c.setRequestMethod("GET");
            c.setRequestProperty("User-Agent", "pingunaut/wicket-pwnedpasswords-validator");
            c.connect();
            
            Status status = Status.of(c.getResponseCode());
            // if nothing is found or there was an API error, return
            if(!status.equals(Status.PASSWORD_PWNED)) {
            	return status;
            }
            // if there were results, check if your pw hash was pwned
            String result = IOUtils.toString(c.getInputStream(), StandardCharsets.UTF_8);
            String lines[] = result.split("\\r?\\n");
            String hashSuffix = getHashSuffix(pw);
            for(String line : lines) {
            	if(line.split(":")[0].equals(hashSuffix)) {
            		return Status.PASSWORD_PWNED;
            	}
            }
            return Status.PASSWORD_OK;
        } catch (IOException | NoSuchAlgorithmException e) {
            LOG.error("Error checking password for pwnage", e);
            return Status.UNKNOWN_API_ERROR;
        }
    }

	protected Proxy getProxy() {
		return proxy;
	}

	protected boolean shouldFailOnUnknownError() {
		return failOnUnknownError;
	}

	protected RateLimitExceededBehavior getRateLimitExceededBehavior() {
		return rateLimitExceededBehavior;
	}

	protected String getHashPrefix(String pw) throws NoSuchAlgorithmException {
		return sha1(pw).substring(0, 5);
	}
	
	protected String getHashSuffix(String pw) throws NoSuchAlgorithmException {
		return sha1(pw).substring(5);
	}
	
	protected URL getApiUrl(String pw) throws MalformedURLException, NoSuchAlgorithmException {
		return new URL(String.format(API_URL, getHashPrefix(pw)));
	}

	/**
	 * The API allows to check passwords directly. To avoid url encoding issues with
	 * complicated passwords, we use the possibility to check sha1 hashes
	 *
	 * @param pw
	 *            the password
	 * @return sha1 hash of the given password
	 * @throws NoSuchAlgorithmException
	 *             if SHA-1 digest not available
	 */
	protected String sha1(String pw) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		byte[] encodedhash = digest.digest(pw.getBytes(StandardCharsets.UTF_8));
		return Strings.toHexString(encodedhash);
	}

	/**
	 * Allows subclasses to decorate reported errors
	 *
	 * @param error
	 *            the error
	 * @param validatable
	 *            the validatable
	 * @return decorated error
	 */
	protected IValidationError decorate(IValidationError error, IValidatable<String> validatable) {
		return error;
	}

}
