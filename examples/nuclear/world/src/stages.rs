//! First times, end selection and scores for accident stages.
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Boiling,
    CoreUncovered,
    CladdingFailure,
    HydrogenRelease,
    CoreMelt,
    Relocation,
    VesselBreach,
    HydrogenBurn,
    ContainmentFailure,
    FloorMeltThrough,
    TurbineHallSteam,
    ControlRoomUninhabitable,
}
impl Stage {
    pub const MAX_JSON_BYTES: usize = 28;
    pub const ALL: [Self; 12] = [
        Self::Boiling,
        Self::CoreUncovered,
        Self::CladdingFailure,
        Self::HydrogenRelease,
        Self::CoreMelt,
        Self::Relocation,
        Self::VesselBreach,
        Self::HydrogenBurn,
        Self::ContainmentFailure,
        Self::FloorMeltThrough,
        Self::TurbineHallSteam,
        Self::ControlRoomUninhabitable,
    ];
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|s| *s == self).unwrap()
    }
    pub fn rank(self) -> u8 {
        match self {
            Self::Boiling | Self::TurbineHallSteam => 1,
            Self::CoreUncovered => 2,
            Self::CladdingFailure | Self::HydrogenRelease => 3,
            Self::CoreMelt | Self::Relocation | Self::HydrogenBurn => 4,
            Self::VesselBreach => 5,
            Self::ContainmentFailure | Self::FloorMeltThrough | Self::ControlRoomUninhabitable => 6,
        }
    }
    pub fn is_end(self) -> bool {
        self.rank() == 6
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCause {
    HydrogenBurn,
    Overpressure,
}
impl FailureCause {
    pub const MAX_JSON_BYTES: usize = 15;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct End {
    pub stage: Stage,
    pub at_ms: u64,
}
impl End {
    pub const MAX_JSON_BYTES: usize = 67;
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageLog {
    pub times: [Option<u64>; 12],
    pub end: Option<End>,
}
impl StageLog {
    pub const MAX_JSON_BYTES: usize = 337;
    pub fn mark(&mut self, stage: Stage, at_ms: u64) {
        let first = *self.times[stage.index()].get_or_insert(at_ms);
        if stage.is_end() && self.end.is_none() {
            self.end = Some(End {
                stage,
                at_ms: first,
            });
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Score {
    pub points: u8,
    pub worst_stage: Option<Stage>,
    pub at_ms: Option<u64>,
}
impl Score {
    /// Compare points, then the time bought before the worst rank was reached.
    pub fn compare(&self, other: &Self) -> Ordering {
        self.points
            .cmp(&other.points)
            .then(self.at_ms.cmp(&other.at_ms))
    }
}

pub fn score(log: &StageLog) -> Score {
    let mut worst: Option<(Stage, u64)> = None;
    for stage in Stage::ALL {
        if let Some(at) = log.times[stage.index()]
            && worst.is_none_or(|(s, t)| {
                stage.rank() > s.rank() || (stage.rank() == s.rank() && at < t)
            })
        {
            worst = Some((stage, at));
        }
    }
    let rank = worst.map_or(0, |(s, _)| s.rank());
    Score {
        points: if log.end.is_some() {
            10
        } else {
            [100, 85, 70, 55, 40, 25, 10][usize::from(rank)]
        },
        worst_stage: worst.map(|(s, _)| s),
        at_ms: worst.map(|(_, t)| t),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_times_and_first_end_stay() {
        let mut log = StageLog::default();
        log.mark(Stage::Boiling, 100);
        log.mark(Stage::Boiling, 50);
        assert_eq!(log.times[0], Some(100));
        log.mark(Stage::FloorMeltThrough, 200);
        log.mark(Stage::ContainmentFailure, 300);
        assert_eq!(
            log.end,
            Some(End {
                stage: Stage::FloorMeltThrough,
                at_ms: 200
            })
        );
        assert_eq!(log.times[Stage::ContainmentFailure.index()], Some(300));
    }

    #[test]
    fn points_follow_each_rank_and_end() {
        assert_eq!(score(&StageLog::default()).points, 100);
        for (stage, rank) in Stage::ALL
            .into_iter()
            .zip([1, 2, 3, 3, 4, 4, 5, 4, 6, 6, 1, 6])
        {
            assert_eq!(stage.rank(), rank);
            let mut log = StageLog::default();
            log.mark(stage, 100);
            assert_eq!(
                score(&log).points,
                [100, 85, 70, 55, 40, 25, 10][usize::from(stage.rank())]
            );
            assert_eq!(log.end.is_some(), stage.is_end());
        }
    }

    #[test]
    fn ties_use_the_first_time_at_the_worst_rank() {
        let mut early = StageLog::default();
        early.mark(Stage::HydrogenRelease, 100);
        early.mark(Stage::CladdingFailure, 200);
        early.mark(Stage::Boiling, 50);
        assert_eq!(score(&early).worst_stage, Some(Stage::HydrogenRelease));
        assert_eq!(score(&early).at_ms, Some(100));
        let mut late = StageLog::default();
        late.mark(Stage::CladdingFailure, 300);
        assert_eq!(score(&late).compare(&score(&early)), Ordering::Greater);
        late.mark(Stage::CoreMelt, 400);
        assert_eq!(score(&late).compare(&score(&early)), Ordering::Less);
    }
}
