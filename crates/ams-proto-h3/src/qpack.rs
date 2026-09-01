// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! QPACK (RFC 9204) : la compression des champs d'HTTP/3.
//!
//! # LE PROBLÈME QUE QPACK RÉSOUT, ET QUE HPACK N'AVAIT PAS
//!
//! HPACK suppose que les blocs d'en-têtes arrivent DANS L'ORDRE : sa table
//! dynamique se met à jour au fil des blocs, et le décodeur doit avoir vu le
//! bloc `n` pour lire le bloc `n+1`. Sur TCP, c'est acquis — la couche du
//! dessous livre dans l'ordre ou ne livre pas.
//!
//! **Sur QUIC, ce n'est plus vrai** : deux flux avancent indépendamment, et le
//! bloc du flux 8 peut arriver avant celui du flux 4. Employer HPACK tel quel
//! rendrait le blocage de tête de ligne qu'HTTP/3 venait justement de retirer —
//! non plus dans le transport, mais dans la compression.
//!
//! QPACK y répond en séparant les INSERTIONS des RÉFÉRENCES. Les insertions
//! voyagent sur un flux à part, ordonné ; chaque bloc dit de combien
//! d'insertions il dépend, et le décodeur ne bloque que si elles ne sont pas
//! encore arrivées. Un encodeur qui ne référence rien de dynamique ne bloque
//! jamais personne — et c'est le mode que ce serveur emploie par défaut.

mod instruction;
mod prefix;
mod representation;
mod section;
mod table_statique;

pub use instruction::{
    DecodedInstruction, DecoderInstruction, EncoderInstruction, EncoderInstructionKind,
    INSTRUCTION_OCTETS_MAX, check_decoder_instruction, check_encoder_instruction,
    check_encoder_instruction_kind, encoder_instruction_kind, read_decoder_instruction,
    read_encoder_instruction, write_decoder_instruction,
};
pub use prefix::{Prefix, max_entries, read_prefix};
pub use representation::{Decoded, FieldLine, Table, read_field_line};
pub use section::{read_section, write_section};
pub use table_statique::{STATIQUE, STATIQUE_LEN, entree_statique};
