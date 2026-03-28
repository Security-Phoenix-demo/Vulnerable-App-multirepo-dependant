package fixtures.owasp.a04;

public class A04_InsecureDesign {
    public boolean allowMoneyTransfer(String accountId, double amount) {
        // Intentionally vulnerable: no limits, no anti-abuse controls, no fraud checks.
        return amount > 0;
    }
}
