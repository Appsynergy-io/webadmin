/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use leptos::*;

use crate::{
    components::messages::alert::{use_alerts, Alert, Alerts},
    core::{
        oauth::use_authorization,
        webauthn::{
            is_webauthn_supported, webauthn_delete, webauthn_list, webauthn_register_flow,
            CredentialInfo,
        },
    },
};

#[component]
pub fn Passkeys() -> impl IntoView {
    let auth = use_authorization();
    let alert = use_alerts();
    let name = create_rw_signal(String::new());
    let list = create_rw_signal::<Option<Vec<CredentialInfo>>>(None);
    let pending = create_rw_signal(false);

    let supported = is_webauthn_supported();

    let refresh = move || {
        spawn_local(async move {
            let token = auth.get_untracked().access_token.to_string();
            match webauthn_list(&token).await {
                Ok(items) => list.set(Some(items)),
                Err(err) => alert.set(Alert::from(err)),
            }
        });
    };
    refresh();

    let add_passkey = move |_| {
        let name_val = name.get().trim().to_string();
        if name_val.is_empty() {
            alert.set(Alert::warning("Enter a name for this passkey"));
            return;
        }
        pending.set(true);
        spawn_local(async move {
            let token = auth.get_untracked().access_token.to_string();
            match webauthn_register_flow(&token, &name_val).await {
                Ok(_) => {
                    alert.set(Alert::success(format!("Passkey '{name_val}' enrolled")));
                    name.set(String::new());
                    let token = auth.get_untracked().access_token.to_string();
                    match webauthn_list(&token).await {
                        Ok(items) => list.set(Some(items)),
                        Err(err) => alert.set(Alert::from(err)),
                    }
                }
                Err(err) => alert.set(err),
            }
            pending.set(false);
        });
    };

    let delete_passkey = move |id: String| {
        spawn_local(async move {
            let token = auth.get_untracked().access_token.to_string();
            match webauthn_delete(&token, &id).await {
                Ok(()) => {
                    alert.set(Alert::success("Passkey removed"));
                    let token = auth.get_untracked().access_token.to_string();
                    match webauthn_list(&token).await {
                        Ok(items) => list.set(Some(items)),
                        Err(err) => alert.set(Alert::from(err)),
                    }
                }
                Err(err) => alert.set(Alert::from(err)),
            }
        });
    };

    view! {
        <div class="max-w-3xl mx-auto w-full p-4 sm:p-6 space-y-6">
            <div>
                <h1 class="text-2xl font-bold dark:text-white">Passkeys</h1>
                <p class="text-sm text-gray-600 dark:text-gray-400 mt-1">
                    Register hardware security keys or platform authenticators (Touch ID,
                    Windows Hello) to sign in without a password.
                </p>
            </div>

            <Alerts/>

            <Show
                when=move || supported
                fallback=|| view! {
                    <div class="rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200">
                        Your browser does not support WebAuthn / passkeys.
                    </div>
                }
            >
                <div class="rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800">
                    <h2 class="text-lg font-semibold dark:text-white">Add a passkey</h2>
                    <div class="mt-3 flex flex-col sm:flex-row gap-3">
                        <input
                            type="text"
                            placeholder="e.g. My laptop, YubiKey"
                            class="flex-1 py-2.5 px-3 block rounded-lg border border-gray-300 text-sm dark:bg-slate-900 dark:border-gray-700 dark:text-gray-200"
                            prop:value=name
                            on:input=move |ev| name.set(event_target_value(&ev))
                        />
                        <button
                            type="button"
                            class="py-2.5 px-4 inline-flex justify-center items-center gap-x-2 text-sm font-semibold rounded-lg border border-transparent bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:pointer-events-none"
                            prop:disabled=pending
                            on:click=add_passkey
                        >
                            {move || if pending.get() { "Waiting..." } else { "Enroll passkey" }}
                        </button>
                    </div>
                </div>
            </Show>

            <div class="rounded-lg border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800">
                <div class="p-4 border-b border-gray-200 dark:border-gray-700">
                    <h2 class="text-lg font-semibold dark:text-white">Enrolled passkeys</h2>
                </div>
                {move || match list.get() {
                    None => view! {
                        <div class="p-4 text-sm text-gray-500 dark:text-gray-400">Loading...</div>
                    }.into_view(),
                    Some(items) if items.is_empty() => view! {
                        <div class="p-4 text-sm text-gray-500 dark:text-gray-400">
                            No passkeys enrolled yet.
                        </div>
                    }.into_view(),
                    Some(items) => view! {
                        <ul class="divide-y divide-gray-200 dark:divide-gray-700">
                            <For
                                each=move || items.clone()
                                key=|c| c.id.clone()
                                children=move |c| {
                                    let id = c.id.clone();
                                    let on_delete = move |_| delete_passkey(id.clone());
                                    view! {
                                        <li class="flex items-center justify-between p-4">
                                            <div>
                                                <div class="font-medium dark:text-white">
                                                    {c.name.clone()}
                                                </div>
                                                <div class="text-xs text-gray-500 dark:text-gray-400">
                                                    "id: " {c.id.chars().take(16).collect::<String>()}...
                                                </div>
                                            </div>
                                            <button
                                                type="button"
                                                class="text-red-600 text-sm hover:underline"
                                                on:click=on_delete
                                            >
                                                Remove
                                            </button>
                                        </li>
                                    }
                                }
                            />
                        </ul>
                    }.into_view(),
                }}
            </div>
        </div>
    }
}
