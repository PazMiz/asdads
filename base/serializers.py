
from rest_framework import serializers
from .models import Product,Category
from .models import Topic

class TopicSerializer(serializers.ModelSerializer):
    class Meta:
        model = Topic
        fields = '__all__'


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ('name',)

class ProductSerializer(serializers.ModelSerializer):
    category = serializers.CharField(source='category.name')

    class Meta:
        model = Product
        fields = ['id', 'desc', 'price', 'image', 'category']

    def create(self, validated_data):
        category = validated_data.pop('category')['name']
        category, _ = Category.objects.get_or_create(name=category)
        validated_data['category'] = category
        product = Product.objects.create(**validated_data)
        return product
    


