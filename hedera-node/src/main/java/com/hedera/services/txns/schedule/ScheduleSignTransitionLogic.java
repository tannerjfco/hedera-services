package com.hedera.services.txns.schedule;

import com.hedera.services.context.TransactionContext;
import com.hedera.services.ledger.HederaLedger;
import com.hedera.services.store.schedule.ScheduleStore;
import com.hedera.services.txns.TransitionLogic;
import com.hedera.services.txns.validation.OptionValidator;
import com.hederahashgraph.api.proto.java.ResponseCodeEnum;
import com.hederahashgraph.api.proto.java.ScheduleSignTransactionBody;
import com.hederahashgraph.api.proto.java.TransactionBody;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.function.Function;
import java.util.function.Predicate;

import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.FAIL_INVALID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.INVALID_SCHEDULE_ID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.OK;

public class ScheduleSignTransitionLogic implements TransitionLogic {
    private static final Logger log = LogManager.getLogger(ScheduleSignTransitionLogic.class);

    private final Function<TransactionBody, ResponseCodeEnum> SYNTAX_CHECK = this::validate;

    OptionValidator validator;
    ScheduleStore store;
    HederaLedger ledger;
    TransactionContext txnCtx;

    public ScheduleSignTransitionLogic(
            OptionValidator validator,
            ScheduleStore store,
            HederaLedger ledger,
            TransactionContext txnCtx) {
        this.validator = validator;
        this.store = store;
        this.ledger = ledger;
        this.txnCtx = txnCtx;
    }

    @Override
    public void doStateTransition() {
        try {
            transitionFor(txnCtx.accessor().getTxn().getScheduleSign());
        } catch (Exception e) {
            log.warn("Unhandled error while processing :: {}!", txnCtx.accessor().getSignedTxn4Log(), e);
            abortWith(FAIL_INVALID);
        }
    }

    private void transitionFor(ScheduleSignTransactionBody op) {
        throw new UnsupportedOperationException();
    }

    private void abortWith(ResponseCodeEnum cause) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Predicate<TransactionBody> applicability() {
        return TransactionBody::hasScheduleSign;
    }

    @Override
    public Function<TransactionBody, ResponseCodeEnum> syntaxCheck() {
        return SYNTAX_CHECK;
    }

    public ResponseCodeEnum validate(TransactionBody txnBody) {
        ScheduleSignTransactionBody op = txnBody.getScheduleSign();

        if (!op.hasScheduleID()) {
            return INVALID_SCHEDULE_ID;
        }
        return OK;
    }
}
