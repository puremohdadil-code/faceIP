package com.sentinelmesh.scheduler;

import java.time.Duration;

public record SchedulePolicy(Duration interval, int maxTargets) {
    public SchedulePolicy {
        if (interval.isZero() || interval.isNegative()) throw new IllegalArgumentException("interval must be positive");
        if (maxTargets < 1) throw new IllegalArgumentException("maxTargets must be positive");
    }

    public boolean allowsTargetCount(int count) {
        return count >= 0 && count <= maxTargets;
    }
}
