package de.martinspielmann.wicket.pwnedpasswordsvalidator;


/**
 * Requests to the breaches and pastes APIs are limited to one per every 1500 milliseconds each
 * from any given IP address (an address may request both APIs within this period).
 * Any request that exceeds the limit will receive an HTTP 429 "Too many requests" response.
 *
 * @author Martin Spielmann
 */
public enum RateLimitExceededBehavior {
    FAIL, RETRY, IGNORE
}
