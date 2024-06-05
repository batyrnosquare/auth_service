package mongodb

import (
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"sso/internal/models"
	"sso/internal/storage"
	"strings"
)

type Storage struct {
	DB *mongo.Client
}

func New(storagePath string) (*Storage, error) {
	const op = "storage.mongodb.New"

	db, err := mongo.Connect(context.Background(), options.Client().ApplyURI(storagePath))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &Storage{DB: db}, nil

}
func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (primitive.ObjectID, error) {
	const op = "storage.mongodb.SaveUser"

	collection := s.DB.Database("pizzeria").Collection("users")
	user := models.User{
		Email:    email,
		PassHash: passHash,
	}
	result, err := collection.InsertOne(ctx, user)
	if err != nil {
		var writeException mongo.WriteException
		if errors.As(err, &writeException) {
			for _, we := range writeException.WriteErrors {
				if we.Code == 11000 {
					return primitive.NilObjectID, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
				}
			}
		}
		if strings.Contains(err.Error(), "users_uc_email") {
			return primitive.NilObjectID, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}
		return primitive.NilObjectID, fmt.Errorf("%s: %w", op, err)
	}

	insertedID := result.InsertedID.(primitive.ObjectID)
	return insertedID, nil
}

func (s *Storage) UserByEmail(ctx context.Context, email string) (models.User, error) {
	const op = "storage.mongodb.User"

	collection := s.DB.Database("pizzeria").Collection("users")

	var user models.User
	filter := bson.M{"email": email}
	err := collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	return user, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userID primitive.ObjectID) (bool, error) {
	const op = "storage.mongodb.IsAdmin"

	collection := s.DB.Database("pizzeria").Collection("users")

	var user bool
	err := collection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return user, nil
}

func (s *Storage) App(ctx context.Context, appID int) (models.App, error) {
	const op = "storage.mongodb.App"

	collection := s.DB.Database("pizzeria").Collection("apps")

	var app models.App
	filter := bson.M{"id": appID}
	err := collection.FindOne(ctx, filter).Decode(&app)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	return app, nil
}
