import React, { useEffect, useState } from "react";
import { KeyRound, UserRound } from "lucide-react";
import { api } from "../api.js";
import { Panel, Message } from "../components/Panel.jsx";

export function ProfileTab({ refreshUser }) {
  const [profile, setProfile] = useState(null);
  const [msg, setMsg] = useState("");
  const [imageFile, setImageFile] = useState(null);
  const [imageKey, setImageKey] = useState(Date.now());
  const [passwords, setPasswords] = useState({ current_password: "", new_password: "", confirm_password: "" });

  async function load() {
    try {
      const r = await api("/api/profile");
      setProfile(r.profile || r);
      setImageKey(Date.now());
    } catch (err) {
      setMsg(err.message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function saveProfile() {
    try {
      const r = await api("/api/profile", { method: "POST", body: profile });
      setMsg(r.message);
      await load();
      refreshUser?.();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function uploadProfileImage() {
    if (!imageFile) {
      setMsg("Please choose a profile image first.");
      return;
    }

    try {
      const form = new FormData();
      form.append("image", imageFile);
      const r = await api("/api/profile/image", { method: "POST", body: form });
      setMsg(r.message || "Profile image updated.");
      setImageFile(null);
      await load();
      refreshUser?.();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function changePassword() {
    try {
      const r = await api("/api/profile/password", { method: "POST", body: passwords });
      setMsg(r.message);
      setPasswords({ current_password: "", new_password: "", confirm_password: "" });
    } catch (err) {
      setMsg(err.message);
    }
  }

  if (!profile) return <Panel title="Profile" icon={UserRound}>Loading...</Panel>;

  const imageSrc = profile.profile_image ? `${profile.profile_image}?v=${imageKey}` : "";

  return (
    <section className="page-grid">
      <Panel title="Profile Details" icon={UserRound}>
        <Message text={msg} />
        <div className="profile-head">
          {imageSrc ? (
            <img src={imageSrc} alt="Profile" />
          ) : (
            <div className="avatar-fallback">
              {String(profile.display_name || profile.username).slice(0, 2).toUpperCase()}
            </div>
          )}
          <div>
            <h2>{profile.display_name || profile.username}</h2>
            <p>
              {profile.role} · {profile.company}
            </p>
          </div>
        </div>
        <div className="file-input-row">
          <input
            type="file"
            accept="image/png,image/jpeg,image/webp,image/gif"
            onChange={(e) => setImageFile(e.target.files?.[0] || null)}
          />
          <button className="ghost-btn" onClick={uploadProfileImage}>
            Upload Image
          </button>
        </div>
        <p className="muted small">Allowed: png, jpg, jpeg, webp, gif · Max 2 MB</p>
        <div className="form-grid">
          <input
            value={profile.display_name || ""}
            onChange={(e) => setProfile({ ...profile, display_name: e.target.value })}
            placeholder="Display name"
          />
          <input
            value={profile.email || ""}
            onChange={(e) => setProfile({ ...profile, email: e.target.value })}
            placeholder="Registered email"
          />
          <input
            value={profile.phone || ""}
            onChange={(e) => setProfile({ ...profile, phone: e.target.value })}
            placeholder="Phone number"
          />
          <input
            value={profile.company || ""}
            onChange={(e) => setProfile({ ...profile, company: e.target.value })}
            placeholder="Company"
          />
          <input
            value={profile.job_title || ""}
            onChange={(e) => setProfile({ ...profile, job_title: e.target.value })}
            placeholder="Job title"
          />
          <input
            value={profile.department || ""}
            onChange={(e) => setProfile({ ...profile, department: e.target.value })}
            placeholder="Department"
          />
          <button className="primary-btn" onClick={saveProfile}>
            Save Profile
          </button>
        </div>
      </Panel>
      <Panel title="Password" icon={KeyRound}>
        <div className="form-grid">
          <input
            type="password"
            placeholder="Current password"
            value={passwords.current_password}
            onChange={(e) => setPasswords({ ...passwords, current_password: e.target.value })}
          />
          <input
            type="password"
            placeholder="New password"
            value={passwords.new_password}
            onChange={(e) => setPasswords({ ...passwords, new_password: e.target.value })}
          />
          <input
            type="password"
            placeholder="Confirm password"
            value={passwords.confirm_password}
            onChange={(e) => setPasswords({ ...passwords, confirm_password: e.target.value })}
          />
          <button className="primary-btn" onClick={changePassword}>
            Change Password
          </button>
        </div>
      </Panel>
    </section>
  );
}
