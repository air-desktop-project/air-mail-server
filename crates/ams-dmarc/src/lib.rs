//! DMARC (RFC 7489) : évaluation d'alignement et de politique, **sans
//! entrée-sortie** (C1, C9).
//!
//! Consomme les verdicts de [`ams_spf`] et [`ams_dkim`], vérifie leur alignement
//! avec le domaine de `From:`, et applique la politique publiée par ce domaine.
//!
//! # État
//!
//! **Rien n'est implémenté.** Emplacement réservé.

#![no_std]
