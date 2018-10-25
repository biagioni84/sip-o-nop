package something.hacky;
import gov.nist.javax.sip.TlsSecurityPolicy;
import gov.nist.javax.sip.ClientTransactionExt;

public class Trusty implements TlsSecurityPolicy{
    public void enforceTlsPolicy(ClientTransactionExt transaction) throws SecurityException {
    }
    }

