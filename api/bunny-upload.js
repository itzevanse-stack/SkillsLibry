// api/bunny-upload.js
// Creates a video slot in Bunny Stream and returns the upload URL
// Called from instructor portal when uploading a lesson video

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const { title, courseId, lessonIndex } = req.body;

  if (!title || !courseId) {
    return res.status(400).json({ error: 'title and courseId are required' });
  }

  const BUNNY_LIBRARY_ID = '690865';
  const BUNNY_API_KEY    = process.env.BUNNY_API_KEY; // set in Vercel env vars

  try {
    /* Step 1 — Create a video slot in Bunny Stream */
    const createRes = await fetch(
      `https://video.bunnycdn.com/library/${BUNNY_LIBRARY_ID}/videos`,
      {
        method: 'POST',
        headers: {
          Accept:         'application/json',
          'Content-Type': 'application/json',
          AccessKey:      BUNNY_API_KEY,
        },
        body: JSON.stringify({ title }),
      }
    );

    if (!createRes.ok) {
      const err = await createRes.text();
      console.error('Bunny create error:', err);
      return res.status(500).json({ error: 'Failed to create video slot' });
    }

    const video = await createRes.json();

    /* Return the video ID and upload URL to the client */
    return res.status(200).json({
      videoId:   video.guid,
      uploadUrl: `https://video.bunnycdn.com/library/${BUNNY_LIBRARY_ID}/videos/${video.guid}`,
      embedUrl:  `https://iframe.mediadelivery.net/embed/${BUNNY_LIBRARY_ID}/${video.guid}`,
      cdnUrl:    `https://vz-4ec805fa-2e2.b-cdn.net/${video.guid}/playlist.m3u8`,
    });

  } catch (err) {
    console.error('Bunny upload error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
