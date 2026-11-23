import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return reply({ error: "Method not allowed" }, 405);

  try {
    const url = Deno.env.get("SUPABASE_URL")!;
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !anonKey || !serviceKey) {
      return reply({ error: "The admin-users function is missing its Supabase secrets." }, 500);
    }

    const authHeader = req.headers.get("Authorization") || "";
    const token = authHeader.replace(/^Bearer\s+/i, "");
    if (!token) return reply({ error: "You must be logged in." }, 401);

    const userClient = createClient(url, anonKey, {
      global: { headers: { Authorization: `Bearer ${token}` } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: authData, error: authError } = await userClient.auth.getUser(token);
    if (authError || !authData.user) return reply({ error: "Your session is not valid." }, 401);

    const adminClient = createClient(url, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const { data: ownerProfile, error: ownerError } = await adminClient
      .from("profiles")
      .select("username,is_admin")
      .eq("id", authData.user.id)
      .maybeSingle();

    if (ownerError || !ownerProfile || !ownerProfile.is_admin ||
        String(ownerProfile.username || "").toLowerCase() !== "isaac") {
      return reply({ error: "Not authorised. Only the site owner can manage accounts." }, 403);
    }

    const body = await req.json();
    const action = String(body.action || "");
    const targetUsername = String(body.username || "").trim().toLowerCase();

    if (action === "list") {
      const { data: profiles, error: profileError } = await adminClient
        .from("profiles")
        .select("id,username,is_admin")
        .order("username", { ascending: true });
      if (profileError) throw profileError;
      return reply({ users: profiles || [] });
    }

    if (!/^[a-z0-9_-]{3,20}$/.test(targetUsername)) {
      return reply({ error: "Enter a valid username." }, 400);
    }
    if (targetUsername === "isaac") {
      return reply({ error: "The owner account cannot be changed or deleted here." }, 400);
    }

    const { data: target, error: targetError } = await adminClient
      .from("profiles")
      .select("id,username")
      .ilike("username", targetUsername)
      .maybeSingle();
    if (targetError) throw targetError;
    if (!target) return reply({ error: "Username not found." }, 404);

    if (action === "set_password") {
      const password = String(body.password || "");
      if (password.length < 8 || password.length > 72) {
        return reply({ error: "Password must be between 8 and 72 characters." }, 400);
      }
      const { error } = await adminClient.auth.admin.updateUserById(target.id, { password });
      if (error) throw error;
      return reply({ success: true, username: target.username });
    }

    if (action === "delete") {
      await adminClient.from("scores").delete().eq("user_id", target.id);
      await adminClient.from("game_saves").delete().eq("user_id", target.id);
      const { error } = await adminClient.auth.admin.deleteUser(target.id);
      if (error) throw error;
      return reply({ success: true, username: target.username });
    }

    return reply({ error: "Unknown action." }, 400);
  } catch (error) {
    return reply({ error: error instanceof Error ? error.message : "Unexpected server error." }, 500);
  }
});
