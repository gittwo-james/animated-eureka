package r2

import (
    "context"
    "errors"
    "fmt"
    "net/url"
    "strings"
    "time"

    "citadel-drive/internal/config"

    "github.com/aws/aws-sdk-go-v2/aws"
    awsconfig "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/retry"
    "github.com/aws/aws-sdk-go-v2/service/s3"
    "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

var ErrNotConfigured = errors.New("r2 storage not configured")

type Client struct {
    bucket     string
    presignTTL time.Duration

    s3      *s3.Client
    presign *s3.PresignClient
}

func New(cfg config.Config) (*Client, error) {
    endpoint := strings.TrimSpace(cfg.R2Endpoint)
    bucket := strings.TrimSpace(cfg.R2Bucket)
    accessKey := strings.TrimSpace(cfg.R2AccessKeyID)
    secret := strings.TrimSpace(cfg.R2SecretAccessKey)

    if endpoint == "" || bucket == "" || accessKey == "" || secret == "" {
        return nil, ErrNotConfigured
    }

    presignTTL := time.Duration(cfg.R2PresignTTL) * time.Second
    if presignTTL <= 0 {
        presignTTL = 15 * time.Minute
    }

    if _, err := url.Parse(endpoint); err != nil {
        return nil, fmt.Errorf("invalid r2 endpoint: %w", err)
    }

    ctx := context.Background()
    awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
        awsconfig.WithRegion(cfg.R2Region),
        awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secret, "")),
        awsconfig.WithRetryer(func() aws.Retryer {
            return retry.NewStandard(func(o *retry.StandardOptions) {
                if cfg.R2MaxAttempts > 0 {
                    o.MaxAttempts = cfg.R2MaxAttempts
                }
            })
        }),
        awsconfig.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...any) (aws.Endpoint, error) {
            if service == s3.ServiceID {
                return aws.Endpoint{URL: endpoint, SigningRegion: region, HostnameImmutable: true}, nil
            }
            return aws.Endpoint{}, &aws.EndpointNotFoundError{}
        })),
    )
    if err != nil {
        return nil, fmt.Errorf("load aws config: %w", err)
    }

    s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
        o.UsePathStyle = true
    })

    presignClient := s3.NewPresignClient(s3Client, func(o *s3.PresignOptions) {
        o.Expires = presignTTL
    })

    return &Client{
        bucket:     bucket,
        presignTTL: presignTTL,
        s3:         s3Client,
        presign:    presignClient,
    }, nil
}

func (c *Client) Bucket() string {
    return c.bucket
}

func (c *Client) PresignTTL() time.Duration {
    return c.presignTTL
}

type PresignedURL struct {
    URL            string              `json:"url"`
    SignedHeaders  map[string][]string `json:"signed_headers"`
    ExpiresSeconds int                 `json:"expires_seconds"`
}

func (c *Client) PresignPutObject(ctx context.Context, key string, contentType string) (PresignedURL, error) {
    if c == nil {
        return PresignedURL{}, ErrNotConfigured
    }

    input := &s3.PutObjectInput{
        Bucket:      aws.String(c.bucket),
        Key:         aws.String(key),
        ContentType: aws.String(contentType),
    }

    out, err := c.presign.PresignPutObject(ctx, input)
    if err != nil {
        return PresignedURL{}, err
    }

    return PresignedURL{URL: out.URL, SignedHeaders: out.SignedHeader, ExpiresSeconds: int(c.presignTTL.Seconds())}, nil
}

func (c *Client) PresignGetObject(ctx context.Context, key string, responseContentType string, contentDisposition string) (PresignedURL, error) {
    if c == nil {
        return PresignedURL{}, ErrNotConfigured
    }

    input := &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)}
    if strings.TrimSpace(responseContentType) != "" {
        input.ResponseContentType = aws.String(responseContentType)
    }
    if strings.TrimSpace(contentDisposition) != "" {
        input.ResponseContentDisposition = aws.String(contentDisposition)
    }

    out, err := c.presign.PresignGetObject(ctx, input)
    if err != nil {
        return PresignedURL{}, err
    }

    return PresignedURL{URL: out.URL, SignedHeaders: out.SignedHeader, ExpiresSeconds: int(c.presignTTL.Seconds())}, nil
}

func (c *Client) CreateMultipartUpload(ctx context.Context, key string, contentType string) (string, error) {
    if c == nil {
        return "", ErrNotConfigured
    }

    out, err := c.s3.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
        Bucket:      aws.String(c.bucket),
        Key:         aws.String(key),
        ContentType: aws.String(contentType),
    })
    if err != nil {
        return "", err
    }
    if out.UploadId == nil {
        return "", errors.New("missing upload id")
    }
    return *out.UploadId, nil
}

func (c *Client) PresignUploadPart(ctx context.Context, key string, uploadID string, partNumber int32) (PresignedURL, error) {
    if c == nil {
        return PresignedURL{}, ErrNotConfigured
    }

    out, err := c.presign.PresignUploadPart(ctx, &s3.UploadPartInput{
        Bucket:     aws.String(c.bucket),
        Key:        aws.String(key),
        UploadId:   aws.String(uploadID),
        PartNumber: aws.Int32(partNumber),
    })
    if err != nil {
        return PresignedURL{}, err
    }

    return PresignedURL{URL: out.URL, SignedHeaders: out.SignedHeader, ExpiresSeconds: int(c.presignTTL.Seconds())}, nil
}

func (c *Client) CompleteMultipartUpload(ctx context.Context, key string, uploadID string, parts []types.CompletedPart) error {
    if c == nil {
        return ErrNotConfigured
    }

    _, err := c.s3.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
        Bucket:   aws.String(c.bucket),
        Key:      aws.String(key),
        UploadId: aws.String(uploadID),
        MultipartUpload: &types.CompletedMultipartUpload{
            Parts: parts,
        },
    })
    return err
}

func (c *Client) AbortMultipartUpload(ctx context.Context, key string, uploadID string) error {
    if c == nil {
        return ErrNotConfigured
    }

    _, err := c.s3.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
        Bucket:   aws.String(c.bucket),
        Key:      aws.String(key),
        UploadId: aws.String(uploadID),
    })
    return err
}

func (c *Client) HeadObject(ctx context.Context, key string) (*s3.HeadObjectOutput, error) {
    if c == nil {
        return nil, ErrNotConfigured
    }

    out, err := c.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
    if err != nil {
        return nil, err
    }
    return out, nil
}

func (c *Client) GetObject(ctx context.Context, key string) (*s3.GetObjectOutput, error) {
    if c == nil {
        return nil, ErrNotConfigured
    }

    out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
    if err != nil {
        return nil, err
    }
    return out, nil
}

func (c *Client) DeleteObject(ctx context.Context, key string) error {
    if c == nil {
        return ErrNotConfigured
    }

    _, err := c.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
    return err
}

func (c *Client) ListUploadedParts(ctx context.Context, key string, uploadID string) ([]types.Part, error) {
    if c == nil {
        return nil, ErrNotConfigured
    }

    parts := make([]types.Part, 0)
    var marker *int32

    for {
        out, err := c.s3.ListParts(ctx, &s3.ListPartsInput{
            Bucket:           aws.String(c.bucket),
            Key:              aws.String(key),
            UploadId:          aws.String(uploadID),
            PartNumberMarker: marker,
        })
        if err != nil {
            return nil, err
        }

        parts = append(parts, out.Parts...)

        if out.IsTruncated && out.NextPartNumberMarker != nil {
            marker = out.NextPartNumberMarker
            continue
        }
        break
    }

    return parts, nil
}

func (c *Client) CopyObject(ctx context.Context, srcKey string, dstKey string, contentType string) error {
    if c == nil {
        return ErrNotConfigured
    }

    escKey := url.PathEscape(srcKey)
    escKey = strings.ReplaceAll(escKey, "%2F", "/")
    copySource := fmt.Sprintf("%s/%s", c.bucket, escKey)

    input := &s3.CopyObjectInput{
        Bucket:     aws.String(c.bucket),
        Key:        aws.String(dstKey),
        CopySource: aws.String(copySource),
    }
    if strings.TrimSpace(contentType) != "" {
        input.ContentType = aws.String(contentType)
        input.MetadataDirective = types.MetadataDirectiveReplace
    }

    _, err := c.s3.CopyObject(ctx, input)
    return err
}
