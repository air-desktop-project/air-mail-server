// Le compte, en clair vers le mandataire.
user_pref("mail.accountmanager.accounts", "account1");
user_pref("mail.accountmanager.defaultaccount", "account1");
user_pref("mail.accountmanager.localfoldersserver", "server2");
user_pref("mail.account.account1.server", "server1");
user_pref("mail.account.account1.identities", "id1");
user_pref("mail.server.server1.type", "imap");
user_pref("mail.server.server1.hostname", "127.0.0.1");
user_pref("mail.server.server1.port", @PORT@);
user_pref("mail.server.server1.socketType", 0);
user_pref("mail.server.server1.authMethod", 3);
user_pref("mail.server.server1.userName", "jean");
user_pref("mail.server.server1.name", "jean@example.com");
user_pref("mail.server.server1.login_at_startup", true);
user_pref("mail.server.server1.check_new_mail", true);
user_pref("mail.server.server1.check_time", 1);
user_pref("mail.server.server1.password", "ouvre-toi");
user_pref("mail.server.server1.remember_password", true);
user_pref("mail.server.server2.type", "none");
user_pref("mail.server.server2.hostname", "Local Folders");
user_pref("mail.identity.id1.useremail", "jean@example.com");
user_pref("mail.identity.id1.fullName", "Jean");
user_pref("mail.identity.id1.valid", true);

// **RIEN NE DOIT SORTIR DE CETTE MACHINE.** Un banc qui interroge des serveurs
// de Mozilla mesurerait leur disponibilité autant que la nôtre.
user_pref("network.dns.offline-localhost", false);
user_pref("mailnews.auto_config.guess.enabled", false);
user_pref("mail.provider.suppress_dialog_on_startup", true);
user_pref("mailnews.start_page.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("app.update.enabled", false);
user_pref("extensions.update.enabled", false);
user_pref("browser.search.update", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("mail.shell.checkDefaultClient", false);
user_pref("mail.rights.version", 1);

// On veut qu'il TÉLÉCHARGE, c'est tout l'objet.
user_pref("mail.server.server1.autosync_offline_stores", true);
user_pref("mail.server.server1.offline_download", true);
