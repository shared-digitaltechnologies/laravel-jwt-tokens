<?php

namespace Shrd\Laravel\JwtTokens\DateTime;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Carbon\CarbonInterval;
use Carbon\CarbonPeriod;
use DatePeriod;
use Illuminate\Support\Traits\Macroable;

readonly final class DateRange
{
    use Macroable;

    /**
     * Gives the empty date range.
     *
     * @return self
     */
    public static function empty(): self
    {
        static $instance;

        if(!isset($instance)) {
            $instance = new DateRange(
                lowerBound: CarbonImmutable::maxValue(),
                upperBound: CarbonImmutable::minValue()
            );
        }

        return $instance;
    }

    /**
     * Gives the unbounded date range.
     *
     * @return self
     */
    public static function unbounded(): self
    {
        static $instance;

        if(!isset($instance)) {
            $instance = new DateRange(
                lowerBound: null,
                upperBound: null
            );
        }

        return $instance;
    }

    private static function toCarbon(mixed $value): CarbonImmutable
    {
        if($value === null) return CarbonImmutable::now();
        if(is_numeric($value)) return CarbonImmutable::createFromTimestamp($value);
        if($value instanceof CarbonImmutable) return $value;
        return new CarbonImmutable($value);
    }

    private static function minLowerBound(CarbonImmutable|null ...$dates): ?CarbonImmutable
    {
        $result = CarbonImmutable::maxValue();
        foreach ($dates as $date) {
            if($date === null) return null;

            if($result->gt($date)) {
                $result = $date;
            }
        }

        return $result;
    }

    private static function maxLowerBound(CarbonImmutable|null ...$dates): ?CarbonImmutable
    {
        $result = null;
        foreach ($dates as $date) {
            if($date === null && $result === null) {
                continue;
            }

            if($result === null) {
                $result = $date;
                continue;
            }

            if($date === null) {
                continue;
            }

            if($result->lt($date)) {
                $result = $date;
            }
        }

        return $result;
    }

    private static function minUpperBound(CarbonImmutable|null ...$dates): ?CarbonImmutable
    {
        $result = null;
        foreach ($dates as $date) {
            if($date === null && $result === null) {
                continue;
            }

            if($result === null) {
                $result = $date;
                continue;
            }

            if($date === null) {
                continue;
            }

            if($result->gt($date)) {
                $result = $date;
            }
        }

        return $result;
    }

    private static function maxUpperBound(CarbonImmutable|null ...$dates): ?CarbonImmutable
    {
        $result = CarbonImmutable::minValue();
        foreach ($dates as $date) {
            if($date === null) return null;

            if($result->lt($date)) {
                $result = $date;
            }
        }

        return $result;
    }

    public static function between($start, $stop): self
    {
        $start = self::toCarbon($start);
        $stop = self::toCarbon($stop);

        if($stop->lte($start)) return self::empty();

        return new self($start, $stop);
    }

    public static function till($stop): self
    {
        $stop = self::toCarbon($stop);
        return new self(null, $stop);
    }

    public static function after($start): self
    {
        $start = self::toCarbon($start);
        return new self(null, $start);
    }

    public static function fromPeriod(DatePeriod $period): self
    {
        $start = $period->getStartDate();
        $end = $period->getEndDate();

        if($end === null) {
            return self::after($start);
        } else {
            return self::between($start, $end);
        }
    }

    public static function fromBounds($lowerBound, $upperBound): self
    {
        if($lowerBound === null && $upperBound === null) return self::unbounded();
        if($lowerBound === null) return self::till($upperBound);
        if($upperBound === null) return self::after($lowerBound);
        return self::between($lowerBound, $upperBound);
    }

    public static function intersection(self ...$ranges): self
    {
        $result = self::unbounded();
        foreach ($ranges as $range) {
            $result = $result->intersect($range);
        }
        return $result;
    }

    public static function spanning(self ...$ranges): self
    {
        $result = self::empty();
        foreach ($ranges as $range) {
            $result = $result->span($range);
        }
        return $result;
    }

    private function __construct(private ?CarbonImmutable $lowerBound,
                                 private ?CarbonImmutable $upperBound)
    {
    }

    public function hasLowerBound(): bool
    {
        return $this->lowerBound !== null;
    }

    public function lowerBound(): ?CarbonInterface
    {
        return $this->lowerBound;
    }

    public function start(): CarbonInterface
    {
        return $this->lowerBound ?? CarbonImmutable::minValue();
    }

    public function hasUpperBound(): bool
    {
        return $this->upperBound !== null;
    }

    public function upperBound(): ?CarbonImmutable
    {
        return $this->upperBound;
    }

    public function stop(): CarbonImmutable
    {
        return $this->upperBound ?? CarbonImmutable::maxValue();
    }

    public function isBounded(): bool
    {
        return $this->lowerBound !== null || $this->upperBound !== null;
    }

    public function isUnbounded(): bool
    {
        return $this->lowerBound === null && $this->upperBound === null;
    }

    public function isEmpty(): bool
    {
        return $this->lowerBound !== null
            && $this->upperBound !== null
            && $this->upperBound->isBefore($this->lowerBound);
    }

    public function seconds(): float
    {
        if($this->isEmpty()) return 0;
        if($this->isBounded()) return $this->start()->floatDiffInSeconds($this->stop());
        return INF;
    }

    public function minutes(): float
    {
        if($this->isEmpty()) return 0;
        if($this->isBounded()) return $this->start()->floatDiffInMinutes($this->stop());
        return INF;
    }

    public function hours(): float
    {
        if($this->isEmpty()) return 0;
        if($this->isBounded()) return $this->start()->floatDiffInHours($this->stop());
        return INF;
    }

    public function days(): float
    {
        if($this->isEmpty()) return 0;
        if($this->isBounded()) return $this->start()->floatDiffInDays($this->stop());
        return INF;
    }

    public function interval(): CarbonInterval
    {
        if($this->isEmpty()) return CarbonInterval::days(0);
        return $this->start()->diffAsCarbonInterval($this->stop());
    }

    private function containsDate($date): bool
    {
        return ($this->lowerBound === null || $this->lowerBound->lte($date))
            && ($this->upperBound === null || $this->upperBound->gte($date));
    }

    public function contains($other): bool
    {
        if($other instanceof DatePeriod) {
            $other = self::fromPeriod($other);
        }

        if($other instanceof self) {
            if($other->lowerBound === null) {
                if($this->hasLowerBound()) return false;
            } else {
                if(!$this->containsDate($other->lowerBound)) return false;
            }

            if($other->upperBound === null) {
                if($this->hasUpperBound()) return false;
            } else {
                if(!$this->containsDate($other->upperBound)) return false;
            }

            return true;
        } else {
            return $this->containsDate($other);
        }
    }

    public function containsNow($tz = null): bool
    {
        return $this->containsDate(CarbonImmutable::now($tz));
    }

    public function intersect(self $other): self
    {
        if($this->isEmpty() || $other->isEmpty()) return self::empty();

        if($this->contains($other)) return $other;
        if($other->contains($this)) return $this;

        $lowerBound = self::maxLowerBound($this->lowerBound, $other->lowerBound);
        $upperBound = self::minUpperBound($this->upperBound, $other->upperBound);

        return self::fromBounds($lowerBound, $upperBound);
    }

    public function span(self $other): self
    {
        if($this->isEmpty() || $other->contains($this)) return $other;
        if($other->isEmpty() || $this->contains($other)) return $this;
        if($this->isUnbounded() || $other->isUnbounded()) return self::unbounded();

        $lowerBound = self::minLowerBound($this->lowerBound, $other->lowerBound);
        $upperBound = self::maxUpperBound($this->upperBound, $other->upperBound);

        return self::fromBounds($lowerBound, $upperBound);
    }

    public function period($interval): CarbonPeriod
    {
        if($this->hasUpperBound()) {
            return new CarbonPeriod(
                $this->start(),
                $interval,
                $this->stop()
            );
        } else {
            return new CarbonPeriod(
                $this->start(),
                $interval,
                INF
            );
        }
    }

}
