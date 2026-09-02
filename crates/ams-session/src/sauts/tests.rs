use super::Sauts;

/// Compte les sauts d'un message donné d'un seul tenant.
fn compter(message: &[u8]) -> u32 {
    let mut sauts = Sauts::new();
    sauts.update(message);
    sauts.count()
}

#[test]
fn un_message_sans_trace_n_a_fait_aucun_saut() {
    assert_eq!(compter(b"From: moi\r\n\r\nbonjour\r\n"), 0);
    assert_eq!(Sauts::default().count(), 0);
}

#[test]
fn chaque_received_compte_pour_un_saut() {
    assert_eq!(
        compter(b"Received: par un\r\nReceived: par deux\r\nFrom: moi\r\n\r\ncorps\r\n"),
        2
    );
}

/// **LA CASSE NE COMPTE PAS** : §2.2 de RFC 5322 veut qu'un nom de champ se
/// compare sans elle.
#[test]
fn la_casse_du_nom_de_champ_ne_compte_pas() {
    assert_eq!(compter(b"RECEIVED: un\r\nrEcEiVeD: deux\r\n\r\n"), 2);
}

/// **CE QUI EST DANS LE CORPS NE COMPTE PAS.** Sans cela, un pair ferait refuser
/// n'importe quel message en écrivant trente lignes dans son texte.
#[test]
fn le_corps_ne_compte_pas() {
    assert_eq!(
        compter(b"From: moi\r\n\r\nReceived: ceci est du texte\r\nReceived: encore\r\n"),
        0
    );
}

/// Un champ REPLIÉ ne compte qu'une fois : sa continuation commence par un
/// blanc, et n'est pas un nouveau champ.
#[test]
fn un_champ_replie_ne_compte_qu_une_fois() {
    assert_eq!(
        compter(b"Received: de loin\r\n\tby nous\r\n\t; hier\r\n\r\n"),
        1
    );
}

/// Un nom qui ressemble sans en être un ne compte pas.
#[test]
fn ce_qui_ressemble_a_received_sans_en_etre_ne_compte_pas() {
    assert_eq!(
        compter(b"Received-SPF: pass\r\nX-Received: un\r\nReceive: deux\r\n\r\n"),
        0
    );
}

/// **LE DÉCOUPAGE DES LECTURES NE CHANGE RIEN** : le compteur ne retient qu'une
/// position, et le réseau choisit où il coupe.
#[test]
fn le_decoupage_des_lectures_ne_change_rien() {
    let message = b"Received: un\r\nRECEIVED: deux\r\nFrom: moi\r\n\r\nReceived: corps\r\n";
    let entier = compter(message);
    assert_eq!(entier, 2);
    for coupe in 0..=message.len() {
        let mut sauts = Sauts::new();
        sauts.update(message.get(..coupe).unwrap_or_default());
        sauts.update(message.get(coupe..).unwrap_or_default());
        assert_eq!(sauts.count(), entier, "coupe à {coupe}");
    }
    // Et octet par octet, la coupe la plus hostile qui soit.
    let mut sauts = Sauts::new();
    for octet in message {
        sauts.update(&[*octet]);
    }
    assert_eq!(sauts.count(), entier);
    assert!(!std::format!("{sauts:?}").is_empty());
}

/// Un message qui n'a pas de corps du tout compte quand même ses en-têtes.
///
/// **LE SAUT SE COMPTE AU DEUX-POINTS**, et non à la fin de la ligne : le nom du
/// champ est alors complet, et rien de ce qui suit ne peut le défaire. La phase
/// de données, elle, n'accepte de toute façon aucune ligne sans `CRLF`.
#[test]
fn un_saut_se_compte_des_que_son_nom_est_complet() {
    assert_eq!(compter(b"Received: un\r\n"), 1);
    assert_eq!(compter(b"Received:"), 1, "le nom suffit");
    assert_eq!(
        compter(b"Received"),
        0,
        "sans deux-points, ce n'est pas un champ"
    );
}
