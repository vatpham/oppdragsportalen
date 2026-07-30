import { NextResponse } from "next/server";
import { createSupabaseServer } from "@/lib/supabase/server";
import { createSupabaseAdmin } from "@/lib/supabase/admin";

function sanitizeUsername(base: string) {
  return (
    base
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "")
      .slice(0, 24) || "user"
  );
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");

  if (!code) {
    return NextResponse.redirect(new URL("/login", url.origin));
  }

  const supabase = await createSupabaseServer();

  const { data, error } = await supabase.auth.exchangeCodeForSession(code);

  if (error || !data.user) {
    console.error("OAuth exchange failed:", error);
    return NextResponse.redirect(new URL("/login", url.origin));
  }

  const user = data.user;
  const admin = createSupabaseAdmin();

  const { data: existingProfile, error: profileError } = await admin
    .from("profiles")
    .select("id")
    .eq("id", user.id)
    .maybeSingle();

  if (profileError) {
    console.error("Failed to check profile:", profileError);
    return NextResponse.redirect(new URL("/login", url.origin));
  }

  if (!existingProfile) {
    const base = sanitizeUsername(
      user.user_metadata?.user_name ?? user.email?.split("@")[0] ?? "user",
    );

    let created = false;

    let i = 0;
    while (true) {
      const username = i === 0 ? base : `${base}${i}`;

      const { error: insertError } = await admin.from("profiles").insert({
        id: user.id,
        username,
        display_name:
          user.user_metadata?.full_name ?? user.user_metadata?.name ?? base,
        avatar_url: user.user_metadata?.avatar_url,
      });

      if (!insertError) {
        created = true;
        break;
      }

      if (insertError.code === "23505") {
        // Try next suffix if duplicate username
        if (insertError.message.includes("profiles_username_key")) {
          i++;
          continue;
        }

        // Check if another request already created the profile
        if (insertError.message.includes("profiles_pkey")) {
          created = true;
          break;
        }
      }

      console.error("Failed to create profile:", insertError);
      return NextResponse.redirect(new URL("/login", url.origin));
    }

    if (!created) {
      console.error("Unable to generate a unique username.");
      return NextResponse.redirect(new URL("/login", url.origin));
    }
  }

  return NextResponse.redirect(new URL("/dashboard", url.origin));
}
