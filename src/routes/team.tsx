import { createFileRoute } from '@tanstack/react-router';
import { PageHeading } from '@/components/deadbyte/workspace';
import { Linkedin } from 'lucide-react';
import estefanyPhoto from '@/assets/estefany.jpg';

export const Route = createFileRoute('/team')({
  head: () => ({
    meta: [
      { title: 'Team Biography — DeadByte' },
      {
        name: 'description',
        content:
          'DeadByte was built by a student team for NWIT 263 · Fall 2026. Every byte leaves a trace — and so does every teammate.',
      },
      { property: 'og:title', content: 'Team Biography — DeadByte' },
      {
        property: 'og:description',
        content:
          'DeadByte was built by a student team for NWIT 263 · Fall 2026. Every byte leaves a trace — and so does every teammate.',
      },
      { property: 'og:type', content: 'website' },
      { name: 'twitter:card', content: 'summary_large_image' },
    ],
  }),
  component: TeamBiography,
});

interface TeamMember {
  initials: string;
  name: string;
  bio: string;
  photo?: string;
  linkedin?: string;
}

const TEAM_MEMBERS: TeamMember[] = [
  {
    initials: 'DE',
    name: 'Dagim Endalafer',
    bio: 'Team member on the DeadByte project.',
    linkedin: 'https://www.linkedin.com/in/dagim-endalafer-247235391',
  },
  {
    initials: 'JT',
    name: 'Jacob Tudge',
    bio: 'Team member on the DeadByte project.',
  },
  {
    initials: 'ER',
    name: 'Estefany Robles',
    bio: 'Team member on the DeadByte project.',
    photo: estefanyPhoto,
    linkedin: 'https://www.linkedin.com/in/estefany-robles-ruiz-6836b12b9',
  },
  {
    initials: 'DH',
    name: 'Dellina Hintsa Asmelash',
    bio: 'Team member on the DeadByte project.'
    linkedin: 'https://www.linkedin.com/in/dellina-asmelash-bb1578384',
  },
];

function TeamBiography() {
  return (
    <div className="page">
      <PageHeading
        eyebrow="ABOUT"
        title="Team Biography"
        description="DeadByte was built by a student team for NWIT 263 · Fall 2026. Every byte leaves a trace — and so does every teammate."
      />

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
          gap: '20px',
          alignItems: 'stretch',
        }}
      >
        {TEAM_MEMBERS.map((member) => (
          <article
            key={member.name}
            style={{
              background: 'var(--card)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '24px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              minHeight: '215px',
            }}
          >
            <div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '16px',
                  marginBottom: '20px',
                }}
              >
                {member.photo ? (
                  <img
                    src={member.photo}
                    alt={member.name}
                    style={{
                      width: '62px',
                      height: '62px',
                      borderRadius: '9999px',
                      objectFit: 'cover',
                      border: '1.5px solid color-mix(in oklch, var(--primary) 45%, var(--border))',
                      flexShrink: 0,
                    }}
                  />
                ) : (
                  <div
                    style={{
                      width: '62px',
                      height: '62px',
                      borderRadius: '9999px',
                      background: 'color-mix(in oklch, var(--primary) 16%, var(--background))',
                      border: '1.5px solid color-mix(in oklch, var(--primary) 40%, var(--border))',
                      color: 'var(--violet)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '16px',
                      fontWeight: 800,
                      letterSpacing: '0.02em',
                      flexShrink: 0,
                    }}
                  >
                    {member.initials}
                  </div>
                )}

                <h2
                  style={{
                    fontSize: '16px',
                    fontWeight: 700,
                    color: 'var(--foreground)',
                    margin: 0,
                  }}
                >
                  {member.name}
                </h2>
              </div>

              <p
                style={{
                  fontSize: '12px',
                  color: 'var(--muted-foreground)',
                  margin: 0,
                  lineHeight: 1.5,
                }}
              >
                {member.bio}
              </p>
            </div>

            {member.linkedin && (
              <div
                style={{
                  marginTop: '20px',
                  paddingTop: '16px',
                  borderTop: '1px solid var(--border)',
                  display: 'flex',
                  alignItems: 'center',
                }}
              >
                <a
                  href={member.linkedin}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={`${member.name} LinkedIn`}
                  title={`${member.name} on LinkedIn`}
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '6px',
                    border: '1px solid var(--border)',
                    background: 'var(--background)',
                    color: 'var(--muted-foreground)',
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <Linkedin size={15} />
                </a>
              </div>
            )}
          </article>
        ))}
      </div>
    </div>
  );
}
