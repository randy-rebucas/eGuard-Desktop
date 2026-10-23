//! Which Windows accounts are the child's (spec section 4; open question Q2, settled 2026-10-23).
//!
//! On a family PC the parent's own account must not be limited or counted. At pairing the parent picks the child's
//! accounts; preselected are the standard (non-administrator) ones, since a parent's account is usually an
//! administrator. Only those accounts' sessions are enforced. An account added later isn't enforced until an
//! administrator adds it, and the parent hears about it (`TAMPER` `NEW_ACCOUNT`).
//!
//! A computer paired before this choice existed has none (`None` in `Persisted`): every account is enforced, the
//! stricter reading.

use crate::wire::ReportedAccount;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A Windows account on this computer, as the platform lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// `S-1-5-21-…`, the account's identity (names can be changed).
    pub sid: String,
    pub name: String,
    /// In the Administrators group.
    pub admin: bool,
}

/// The parent's choice, kept with the device's state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountChoice {
    /// The child's accounts, by SID.
    pub enforced: BTreeSet<String>,
    /// Every account seen so far, by SID: one not in here is new.
    pub known: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("there's no Windows account called {0:?} on this computer")]
pub struct UnknownAccount(pub String);

impl AccountChoice {
    /// The preselection: every standard account.
    pub fn standard(accounts: &[Account]) -> Self {
        Self {
            enforced: accounts.iter().filter(|a| !a.admin).map(|a| a.sid.clone()).collect(),
            known: accounts.iter().map(|a| a.sid.clone()).collect(),
        }
    }

    /// The accounts named (any case). Every account becomes known.
    pub fn named(accounts: &[Account], names: &[String]) -> Result<Self, UnknownAccount> {
        let mut enforced = BTreeSet::new();
        for n in names.iter().map(|n| n.trim()).filter(|n| !n.is_empty()) {
            let a = accounts.iter().find(|a| a.name.eq_ignore_ascii_case(n)).ok_or_else(|| UnknownAccount(n.to_owned()))?;
            enforced.insert(a.sid.clone());
        }
        Ok(Self { enforced, known: accounts.iter().map(|a| a.sid.clone()).collect() })
    }

    pub fn applies(&self, sid: &str) -> bool {
        self.enforced.contains(sid)
    }

    /// Accounts not seen before, now remembered as known (and not enforced).
    pub fn take_new<'a>(&mut self, accounts: &'a [Account]) -> Vec<&'a Account> {
        accounts.iter().filter(|a| self.known.insert(a.sid.clone())).collect()
    }
}

/// Whether the child's rules apply in the account `sid`, given the choice (or none: every account).
pub fn applies(choice: Option<&AccountChoice>, sid: &str) -> bool {
    choice.is_none_or(|c| c.applies(sid))
}

/// What `/report` says: each account's name and whether the rules apply in it.
pub fn report(choice: Option<&AccountChoice>, accounts: &[Account]) -> Vec<ReportedAccount> {
    accounts
        .iter()
        .take(32)
        .map(|a| ReportedAccount { name: a.name.chars().take(64).collect(), enforced: applies(choice, &a.sid) })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accounts() -> Vec<Account> {
        vec![
            Account { sid: "S-1-5-21-1-1001".into(), name: "Carla".into(), admin: true },
            Account { sid: "S-1-5-21-1-1002".into(), name: "Mia".into(), admin: false },
            Account { sid: "S-1-5-21-1-1003".into(), name: "Leo".into(), admin: false },
        ]
    }

    #[test]
    fn standard_accounts_are_preselected_and_the_parents_admin_isnt() {
        let c = AccountChoice::standard(&accounts());
        assert!(!c.applies("S-1-5-21-1-1001"));
        assert!(c.applies("S-1-5-21-1-1002") && c.applies("S-1-5-21-1-1003"));
        assert_eq!(
            report(Some(&c), &accounts()),
            vec![
                ReportedAccount { name: "Carla".into(), enforced: false },
                ReportedAccount { name: "Mia".into(), enforced: true },
                ReportedAccount { name: "Leo".into(), enforced: true }
            ]
        );
    }

    #[test]
    fn the_parent_can_name_them_and_a_wrong_name_is_refused() {
        let c = AccountChoice::named(&accounts(), &["mia".into()]).unwrap();
        assert!(c.applies("S-1-5-21-1-1002") && !c.applies("S-1-5-21-1-1003"));
        assert_eq!(c.known.len(), 3);
        assert_eq!(AccountChoice::named(&accounts(), &["Nobody".into()]).unwrap_err(), UnknownAccount("Nobody".into()));
    }

    #[test]
    fn a_new_account_is_news_once_and_not_enforced() {
        let mut c = AccountChoice::standard(&accounts());
        let mut later = accounts();
        later.push(Account { sid: "S-1-5-21-1-1004".into(), name: "Guesty".into(), admin: false });
        assert_eq!(c.take_new(&later).iter().map(|a| a.name.as_str()).collect::<Vec<_>>(), ["Guesty"]);
        assert_eq!(c.take_new(&later).len(), 0);
        assert!(!c.applies("S-1-5-21-1-1004"));
    }

    #[test]
    fn with_no_choice_every_account_is_enforced() {
        assert!(applies(None, "S-1-5-21-1-1001"));
        assert!(report(None, &accounts()).iter().all(|a| a.enforced));
    }
}
