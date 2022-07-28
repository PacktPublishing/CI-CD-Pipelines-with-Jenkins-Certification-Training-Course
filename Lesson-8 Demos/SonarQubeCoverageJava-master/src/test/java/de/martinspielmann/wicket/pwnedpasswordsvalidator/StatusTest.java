package de.martinspielmann.wicket.pwnedpasswordsvalidator;

import org.junit.Assert;
import org.junit.Test;

public class StatusTest {

    @Test
    public void testStatusOfUnknownCodeResultsInUnknownApiError() {
        Status s = Status.of(234);
        Assert.assertEquals(Status.UNKNOWN_API_ERROR, s);
    }
}