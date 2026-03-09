import React, { useEffect, useState } from "react";

export default function Profile({ userId }) {
  const [profile, setProfile] = useState(null);

  useEffect(() => {
    fetch(`/api/profile/${userId}`)
      .then((res) => res.json())
      .then(setProfile);
  }, [userId]);

  if (!profile) return <div>Loading...</div>;

  return (
    <div className="profile">
      <h2>{profile.name}</h2>
      <div
        className="bio"
        dangerouslySetInnerHTML={{ __html: profile.bio }}
      />
    </div>
  );
}
